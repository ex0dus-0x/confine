//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.
use nix::sys::{ptrace, wait};
use nix::unistd::{self, Pid};
use nix::Error as NixError;

use libc::user_regs_struct;
use unshare::{Command, Namespace};

use serde::Serialize;
use serde_json::{json, Value};

use std::collections::HashMap;
use std::io::Error as IOError;

use crate::policy::{Action, Policy};
use crate::syscall::{ParsedSyscall, SyscallManager};

/// Defines a serializable threat report that is returned to the user by default if not specified
#[derive(Serialize, Default)]
pub struct ThreatReport {
    // stores only the system call names that are encountered
    calls: Vec<String>,

    // stores network addresses that are encountered
    networking: Vec<String>,

    // maps file I/O interactions
    file_io: HashMap<String, String>,

    // external commands executed
    commands: Vec<String>,
}

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // generated Command for spawning when actually tracing
    cmd: Command,

    // encapsulates the `Pid` of the eventually running process
    pid: Pid,

    // optional policy that is to be enforced upon execution
    policy: Option<Policy>,

    // interfaces system call representation parsing
    manager: SyscallManager,

    // generated final report for potential threats and IOCs
    report: ThreatReport,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(args: Vec<String>, policy: Option<Policy>) -> Self {
        // create new unshare-wrapped command with arguments
        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().skip(1) {
            cmd.arg(arg);
        }

        // return mostly with default arguments that gets populated
        Self {
            cmd,
            pid: Pid::from_raw(-1),
            policy,
            manager: SyscallManager::new().unwrap(),
            report: ThreatReport::default(),
        }
    }

    /// Helper that instantiates a containerized environment before the execution of the actual
    /// child process.
    fn init_container_env(&mut self) -> Result<(), NixError> {
        // created isolated namespace by unsharing namespaces
        let namespaces = vec![
            Namespace::User,
            Namespace::Cgroup,
            Namespace::Pid,
            Namespace::Ipc,
        ];
        self.cmd.unshare(&namespaces);

        // initialize cgroup

        // sets the hostname for the new isolated process
        unistd::sethostname("confine")?;

        // mount rootfs
        todo!()
    }

    /// Executes a dynamic `ptrace`-based trace upon the given application specified. Will first
    /// instantiate a containerized environment with unshared namespaces and a seperately mounted
    /// filesystem, and then spawn the tracee. If a `Policy` is specified, rules will also be
    /// enforced.
    pub fn trace(&mut self) -> Result<(), NixError> {
        /// Wraps nix's `ptrace::traceme()` to return a properly consumable IOError
        fn traceme() -> Result<(), IOError> {
            use std::io::ErrorKind;
            match ptrace::traceme() {
                Err(nix::Error::Sys(errno)) => Err(IOError::from_raw_os_error(errno as i32)),
                Err(e) => Err(IOError::new(ErrorKind::Other, e)),
                _ => Ok(()),
            }
        }

        // call traceme helper to signal parent for tracing
        unsafe {
            self.cmd.pre_exec(traceme);
        }

        // spawns a child process handler
        let child = match self.cmd.spawn() {
            Ok(handler) => handler,
            Err(_) => {
                return Err(NixError::last());
            }
        };

        // create nix Pid, save state for later use
        self.pid = Pid::from_raw(child.pid());

        // configure options to trace for syscall interrupt
        // TODO: trace forked childrens
        ptrace::setoptions(self.pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

        // wait for process to change execution state
        wait::waitpid(self.pid, None)?;

        // run loop until broken by end of execution
        loop {
            match self.step() {
                Ok(status) => {
                    // break if successfully completed execution
                    if status == 0 {
                        break;
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        // TODO: unmount the rootfs partition
        Ok(())
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
    fn parse_type(&mut self, typename: &str, mut regval: u64) -> Result<Value, NixError> {
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
                        return Ok(json!(std::str::from_utf8(&buffer).unwrap()));
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

    /// Introspect single event in traced process, using ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<i32, NixError> {
        // encounter SYSCALL_ENTER
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        match wait::waitpid(self.pid, None) {
            Ok(status) => {
                if let wait::WaitStatus::Exited(_, stat) = status {
                    return Ok(stat);
                }
            }
            Err(e) => return Err(e),
        }

        // get register state as this point
        let regstate: user_regs_struct = ptrace::getregs(self.pid)?;

        // get system call number for ORIG_RAX
        let syscall_num: u64 = regstate.orig_rax;

        // parse out arguments to read and write based on syscall table
        let to_read: Vec<String> = self.manager.get_arguments(syscall_num).unwrap();

        // for each argument, get corresponding register in calling convention, and parse
        // accordingly based on the given type
        let mut args: HashMap<String, Value> = HashMap::new();
        for (idx, arg) in to_read.iter().enumerate() {
            // get contents of register in calling convention by index
            let regval: u64 = Tracer::get_reg_idx(regstate, idx as i32);
            if regval == u64::MAX {
                return Err(NixError::invalid_argument());
            }

            // get type and decide if further reading is necessary
            let val: Value = self.parse_type(arg.as_str(), regval)?;

            // commit type and value mapping to hashmap
            args.insert(arg.to_string(), val);
        }

        // after parsing, check to see if a policy is configured and if there is a rule that needs
        // to be enforced upon the system call
        if let Some(policy) = &self.policy {
            // get the syscall name
            let name: String = match self.manager.get_syscall_name(syscall_num) {
                Some(name) => name,
                None => {
                    return Err(NixError::invalid_argument());
                }
            };

            // check if name is set as policy, and get enforcement
            match policy.get_enforcement(&name) {
                Some(action) => {
                    // determine what to be done based on the given action
                    match action {
                        // print warning with syscall but continue execution
                        Action::Warn => {
                            println!("confine: [WARN] encountered syscall {}", name);
                        }

                        // halt execution immediately and return
                        Action::Block => {
                            println!("confine: [BLOCK] encountered syscall {}", name);
                            return Ok(0);
                        }

                        // write parsed syscall to log file
                        Action::Log => {
                            let parsed_syscall: ParsedSyscall =
                                ParsedSyscall::new(name, args.clone());

                            // write to log
                            if let Err(e) = policy.to_log(parsed_syscall) {
                                return Err(NixError::invalid_argument());
                            }
                        }

                        // continue without issue
                        Action::Permit => {}
                    }
                }
                None => {
                    return Err(NixError::invalid_argument());
                }
            };
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args).unwrap();

        // encounter SYSCALL_EXIT
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        match wait::waitpid(self.pid, None) {
            Ok(status) => {
                if let wait::WaitStatus::Exited(_, stat) = status {
                    return Ok(stat);
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
        Ok(-1)
    }

    /// Generates a JSONified dump of the full trace, including arguments.
    pub fn normal_trace(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.manager)
    }

    /// Generates a dump of the trace excluding arguments and including varying capabilities
    /// for detecting potential IOCs
    pub fn threat_trace(&self) -> serde_json::Result<String> {
        unimplemented!()
    }
}
