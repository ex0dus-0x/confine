//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.
use nix::sys::signal::Signal;
use nix::sys::{ptrace, wait};
use nix::unistd::{self, Pid};
use nix::Error as NixError;
use nix::{mount, sched};

use libc::user_regs_struct;

use serde_json::{json, Value};

use std::fs;
use std::io::Error as IOError;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{ConfineError, ConfineResult};
use crate::policy::{Action, Policy};
use crate::syscall::{ArgMap, ParsedSyscall, SyscallManager};
use crate::threat::ThreatReport;

// Wraps nix's `ptrace::traceme()` to return a properly consumable IOError
fn traceme() -> Result<(), IOError> {
    use std::io::ErrorKind;
    match ptrace::traceme() {
        Err(nix::Error::Sys(errno)) => Err(IOError::from_raw_os_error(errno as i32)),
        Err(e) => Err(IOError::new(ErrorKind::Other, e)),
        _ => Ok(()),
    }
}

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // generated Command for spawning when actually tracing
    cmd: Command,

    // path to control groups for process restriction
    cgroups: PathBuf,

    // encapsulates the `Pid` of the eventually running process
    pid: Pid,

    // optional policy that is to be enforced upon execution
    policy: Option<Policy>,

    // interfaces system call representation parsing
    manager: SyscallManager,

    // if set, prints out each syscall dynamically
    verbose_trace: bool,

    // generated final report for potential threats and IOCs
    report: ThreatReport,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(
        args: Vec<String>,
        policy: Option<Policy>,
        verbose_trace: bool,
    ) -> ConfineResult<Self> {
        // create new unshare-wrapped command with arguments
        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().skip(1) {
            cmd.arg(arg);
        }

        // initialize cgroup, check if supported in kernel
        let mut cgroups = PathBuf::from("/sys/fs/cgroup/pids");
        if !cgroups.exists() {
            panic!("Linux kernel does not support cgroups");
        }
        cgroups.push("confine");

        // return mostly with default arguments that gets populated
        Ok(Self {
            cmd,
            cgroups,
            pid: Pid::from_raw(-1),
            policy,
            manager: SyscallManager::new().unwrap(),
            verbose_trace,
            report: ThreatReport::default(),
        })
    }

    /// Encapsulates container runtime creation and process tracing execution under a callback that
    /// is cloned to run.
    pub fn trace(&mut self) -> ConfineResult<()> {
        let stack = &mut [0; 1024 * 1024];
        let callback = Box::new(|| match self.exec_container_trace() {
            Ok(res) => res,
            Err(e) => {
                panic!(e);
            }
        });

        // set namespaces to unshare for the new process
        let clone_flags = sched::CloneFlags::CLONE_NEWNS
            | sched::CloneFlags::CLONE_NEWPID
            | sched::CloneFlags::CLONE_NEWCGROUP
            | sched::CloneFlags::CLONE_NEWUTS
            | sched::CloneFlags::CLONE_NEWIPC
            | sched::CloneFlags::CLONE_NEWNET;

        // clone new process with callback
        sched::clone(callback, stack, clone_flags, Some(Signal::SIGCHLD as i32))?;
        Ok(())
    }

    /*
    fn better_container_env(&mut self) -> ConfineResult<()> {
        // created isolated namespace by unsharing namespaces
        let namespaces = vec![
            Namespace::Mount,   // nable mounting child folders
            Namespace::Pid,     // isolates process so that it appears as PID 1
            Namespace::Uts,     // enables hostname to be changed
            Namespace::User,    // unprvileged user to be root user
            Namespace::Ipc,     // isolate message queues
            Namespace::Cgroup,  // isolate cgroups
        ];
        println!("--> Unsharing namespaces for isolated child process.");
        self.cmd.unshare(&namespaces);

        // saving the CAP_SYS_PTRACE capability
        let caps = vec![Capbility::CAP_SYS_PTRACE];
        self.cmd.keep_caps(caps);

        // chroot the rootfs mount
        self.cmd.chroot_dir("rootfs");
        Ok(())
    }
    */

    /// Helper that instantiates a containerized environment before the execution of the actual
    /// child process.
    fn init_container_env(&mut self) -> ConfineResult<()> {
        sched::unshare(sched::CloneFlags::CLONE_NEWNS)?;

        // keep ptrace capabilities
        unsafe {
            let _ = libc::prctl(libc::SYS_ptrace as i32);
        }

        // initialize new cgroups directory if not found
        if !self.cgroups.exists() {
            println!("--> Initialize cgroups path for restricted resources.");
            fs::create_dir_all(&self.cgroups)?;
            let mut permission = fs::metadata(&self.cgroups)?.permissions();
            permission.set_mode(511);
            fs::set_permissions(&self.cgroups, permission).ok();
        }

        // write to new cgroups directory
        fs::write(self.cgroups.join("pids.max"), b"20")?;
        fs::write(self.cgroups.join("notify_on_release"), b"1")?;
        fs::write(self.cgroups.join("cgroup.procs"), b"0")?;

        // sets the hostname for the new isolated process
        // TODO: make random string
        println!("--> Using new hostname");
        unistd::sethostname("confine")?;

        // mount rootfs and go to root path
        println!("--> Mounting rootfs to root path");
        unistd::chroot("rootfs")?;
        unistd::chdir("/")?;

        // mount the proc file system
        println!("--> Mounting procfs");
        const NONE: Option<&'static [u8]> = None;
        mount::mount(
            Some("proc"),
            "proc",
            Some("proc"),
            mount::MsFlags::empty(),
            NONE,
        )?;
        Ok(())
    }

    /// Executes a dynamic `ptrace`-based trace upon the given application specified. Will first
    /// instantiate a containerized environment with unshared namespaces and a seperately mounted
    /// filesystem, and then spawn the tracee. If a `Policy` is specified, rules will also be
    /// enforced.
    fn exec_container_trace(&mut self) -> ConfineResult<isize> {
        // containerize the environment we are executing under
        self.init_container_env()?;

        // spawns a child process handler
        println!("--> Spawning target executable in containerized environment");
        unsafe {
            self.cmd.pre_exec(traceme);
        }
        let child = self.cmd.spawn()?;

        // create nix Pid, save state for later use
        self.pid = Pid::from_raw(child.id() as i32);

        // configure options to trace for syscall interrupt
        // TODO: trace forked childrens
        ptrace::setoptions(self.pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

        // wait for process to change execution state
        wait::waitpid(self.pid, None)?;

        // run loop until broken by end of execution
        loop {
            if self.step()? == 0 {
                break;
            }
        }

        // unmount the procfs partition
        mount::umount("proc")?;

        // print final trace while still in cloned process
        println!("{}", self.threat_trace()?);
        Ok(0)
    }

    /// Helper that returns the register content given register state and calling convention index.
    #[inline]
    fn get_reg_idx(state: user_regs_struct, idx: i32) -> u64 {
        match idx {
            0 => state.rdi,
            1 => state.rsi,
            2 => state.rdx,
            3 => state.rcx,
            4 => state.r8,
            5 => state.r9,
            _ => u64::MAX,
        }
    }

    /// Helper that parses a register value based on the corresponding type for it, and returns a
    /// genericized `serde_json::Value` to store back into the manager.
    fn parse_type(&mut self, typename: &str, mut regval: u64) -> ConfineResult<Value> {
        // if type is a numeric value, return the register value as is without reading from memory
        // any further. TODO: unsigned and signed distinction and casting.
        let numerics: Vec<&str> = vec![
            "int",
            "unsigned int",
            "long",
            "unsigned long",
            "short",
            "unsigned short",
            // aliases
            "size_t",
            "pid_t",
            "gid_t",
            "qid_t",
            "uid_t",
            "key_t",
            "time_t",
            "clockid_t",
            "umode_t",
            "sigset_t",
            "mqd_t",
            "key_serial_t",
            "rwf_t",
            "off_t",
            "loff_t",
        ];
        if numerics.iter().any(|&i| typename.contains(i)) {
            return Ok(json!(regval));
        }

        // known aliases to structs
        let structs: Vec<&str> = vec![
            "cap_user_header_t",
            "cap_user_data_t",
            "siginfo_t",
            "aio_context_t",
        ];

        // since parsing data structures is a lot of work, just store hex address
        if structs.iter().any(|&i| typename.contains(i)) || typename.contains("struct") {
            return Ok(json!(format!("0x{:x}", regval)));
        }

        // if a char buffer, use ptrace to read from address stored in register
        if typename.contains("char") {
            // instantiate buffer to store contents from read
            let mut buffer: Vec<u8> = Vec::new();
            loop {
                let word = nix::sys::ptrace::read(self.pid, regval as *mut libc::c_void)? as u32;
                let bytes: [u8; 4] = unsafe { std::mem::transmute(word) };
                for byte in bytes.iter() {
                    // break when encountering null byte, or append to buffer
                    if *byte == 0 {
                        let bufstr: &str = std::str::from_utf8(&buffer).unwrap_or("?");
                        return Ok(json!(bufstr));
                    }
                    buffer.push(*byte);
                }
                // increment to read next word
                regval += 4;
            }
        }

        // by default, return memory address if type cannot be parsed out
        Ok(json!(format!("0x{:x}", regval)))
    }

    /// If a policy is parsed and properly configured, check to see if the current input system
    /// call contains a rule that needs to be enforced.
    fn enforce_policy(&mut self, syscall_num: u64, args: &ArgMap) -> ConfineResult<i32> {
        if let Some(policy) = &self.policy {
            // get the syscall name
            let name: String = match self.manager.get_syscall_name(syscall_num) {
                Some(name) => name,
                None => {
                    return Err(ConfineError::SystemError(NixError::invalid_argument()));
                }
            };

            // check if name is set as policy, and get enforcement
            if let Some(action) = policy.get_enforcement(&name) {
                match action {
                    // print warning with syscall but continue execution
                    Action::Warn => {
                        println!("confine: [WARN] encountered syscall {}", name);
                    }

                    // halt execution immediately and return
                    Action::Block => {
                        println!("confine: [BLOCK] encountered syscall {}", name);
                        return Ok(-1);
                    }

                    // write parsed syscall to log file
                    Action::Log => {
                        let parsed_syscall: ParsedSyscall = ParsedSyscall::new(name, args.clone());
                        policy.to_log(parsed_syscall)?;
                    }

                    // continue without issue
                    Action::Permit => {}
                }
            }
        }
        Ok(0)
    }

    /// Implements the main step functionality for tracing one system call, entering the call,
    /// parsing the syscall number and register contents, doing policy enforcement, and exiting
    /// when necessary.
    fn step(&mut self) -> ConfineResult<i32> {
        // encounter SYSCALL_ENTER
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        if let wait::WaitStatus::Exited(_, stat) = wait::waitpid(self.pid, None)? {
            return Ok(stat);
        }

        // get register state as this point
        let regstate: user_regs_struct = ptrace::getregs(self.pid)?;

        // get system call number for ORIG_RAX
        let syscall_num: u64 = regstate.orig_rax;

        // parse out arguments to read and write based on syscall table
        let to_read: Vec<String> = self.manager.get_arguments(syscall_num).unwrap();

        // for each argument, get corresponding register in calling convention, and parse
        // accordingly based on the given type
        let mut args: ArgMap = ArgMap::new();
        for (idx, arg) in to_read.iter().enumerate() {
            // get contents of register in calling convention by index
            let regval: u64 = Tracer::get_reg_idx(regstate, idx as i32);
            if regval == u64::MAX {
                return Err(ConfineError::SystemError(NixError::invalid_argument()));
            }

            // get type and decide if further reading is necessary
            let val: Value = self.parse_type(arg.as_str(), regval)?;

            // commit type and value mapping to hashmap
            args.insert(arg.to_string(), val);
        }

        // at this stage, before commiting and exiting, check if a rule has been set that needs to
        // be enforced
        if self.enforce_policy(syscall_num, &args)? == -1 {
            return Ok(0);
        }

        // add syscall to manager
        let parsed: ParsedSyscall = self.manager.add_syscall(syscall_num, args)?;

        if self.verbose_trace {
            println!("{}", parsed);
        }

        // check to see if any system call behavior needs to be stored in our threat report
        self.report.check(&parsed)?;

        // encounter SYSCALL_EXIT
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        if let wait::WaitStatus::Exited(_, stat) = wait::waitpid(self.pid, None)? {
            return Ok(stat);
        }
        Ok(-1)
    }

    /// Generates a dump of the trace excluding arguments and including varying capabilities
    /// for detecting potential IOCs
    pub fn threat_trace(&mut self) -> ConfineResult<String> {
        // populate threat report with syscalls traced
        self.report.populate(&self.manager.syscalls)?;

        // create final JSON threat report
        let json = serde_json::to_string_pretty(&self.report)?;
        Ok(json)
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.cgroups.exists() {
            fs::remove_dir(&self.cgroups).expect("Cannot delete cgroups path");
        }
    }
}
