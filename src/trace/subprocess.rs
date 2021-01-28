//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use nix::Error as NixError;

use libc::user_regs_struct;

use serde_json::{json, Value};

use std::io::Error as IOError;
use std::os::unix::process::CommandExt;
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

/// Encapsulates a command that is to be traced under the container environment, storing syscall
/// events and enforcing a policy as a "firewall".
pub struct Subprocess {
    // command interface to start traced child
    cmd: Command,

    // stores the pid of the eventually running process being traced
    pid: Pid,

    // policy containing rules for enforcement
    policy: Option<Policy>,

    // interfaces system call representation parsing
    manager: SyscallManager,

    // generated final report for potential threats and IOCs
    report: ThreatReport,
}

impl Subprocess {
    /// Creates new interface with the args to a command in a Confinement, and optionally a
    /// specified policy section.
    pub fn new(args: Vec<String>, policy: Option<Policy>) -> ConfineResult<Self> {
        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().skip(1) {
            cmd.arg(arg);
        }

        log::trace!("Configure PTRACE_TRACEME to be called for debugger");
        unsafe {
            cmd.pre_exec(traceme);
        }

        log::trace!("Initializing syscall manager");
        let manager = SyscallManager::new()?;

        Ok(Self {
            cmd,
            pid: Pid::from_raw(-1),
            policy,
            manager,
            report: ThreatReport::default(),
        })
    }

    /// Executes a trace on the specified command, stepping through each system call with `step()`.
    pub fn trace(&mut self) -> ConfineResult<()> {
        // spawns a child process handler
        log::info!("Spawning target executable in containerized environment");

        log::debug!("Launching child process");
        let child = self.cmd.spawn()?;

        // save Pid, save state for later use
        self.pid = Pid::from_raw(child.id() as i32);
        log::trace!("PID: {:?}", self.pid);

        // configure options to trace for syscall interrupt
        // TODO: trace forked childrens
        log::debug!("Running PTRACE_SETOPTIONS");
        ptrace::setoptions(self.pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

        log::debug!("Waiting for process to change execution state");
        wait::waitpid(self.pid, None)?;

        // run loop until broken by end of execution
        loop {
            if self.step()? == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Implements the main step functionality for tracing one system call, entering the call,
    /// parsing the syscall number and register contents, doing policy enforcement, and exiting
    /// when necessary.
    fn step(&mut self) -> ConfineResult<i32> {
        // encounter SYSCALL_ENTER
        log::trace!("Stepping to next syscall event");
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        log::trace!("Checking if process exited");
        if let wait::WaitStatus::Exited(_, stat) = wait::waitpid(self.pid, None)? {
            return Ok(stat);
        }

        // get register state as this point
        log::trace!("Get state of registers set");
        let regstate: user_regs_struct = ptrace::getregs(self.pid)?;

        // get system call number for ORIG_RAX
        let syscall_num: u64 = regstate.orig_rax;
        log::trace!("Syscall num parsed from ORIG_RAX: {}", syscall_num);

        // parse out arguments to read and write based on syscall table
        log::trace!("Getting arguments for syscall from syscall table");
        let to_read: Vec<String> = self.manager.get_arguments(syscall_num)?;

        // for each argument, get corresponding register in calling convention, and parse
        // accordingly based on the given type
        let mut args: ArgMap = ArgMap::new();

        log::trace!("Parsing each argument given type from syscall table");
        for (idx, arg) in to_read.iter().enumerate() {
            // get contents of register in calling convention by index
            let regval: u64 = Self::get_reg_idx(regstate, idx as i32);

            // get type and decide if further reading is necessary
            let val: Value = self.parse_type(arg, regval)?;

            // commit type and value mapping to hashmap
            args.insert(arg.to_string(), val);
        }

        // at this stage, before commiting and exiting, check if a rule has been set that needs to
        // be enforced
        log::trace!("Checking against policy");
        if self.enforce_policy(syscall_num, &args)? == -1 {
            return Ok(0);
        }

        // add syscall to manager
        log::trace!("Adding to syscall manager");
        let parsed: ParsedSyscall = self.manager.add_syscall(syscall_num, args)?;

        log::info!("{}", parsed);

        // check to see if any system call behavior needs to be stored in our threat report
        log::trace!("Checking if syscall is suspicious");
        self.report.check(&parsed)?;

        // encounter SYSCALL_EXIT
        log::trace!("Step to end of syscall");
        ptrace::syscall(self.pid, None)?;

        // wait for status, return status if finished execution
        log::trace!("Checking if process exited again");
        if let wait::WaitStatus::Exited(_, stat) = wait::waitpid(self.pid, None)? {
            return Ok(stat);
        }
        Ok(-1)
    }

    /// If a policy is parsed and properly configured, check to see if the current input system
    /// call contains a rule that needs to be enforced.
    fn enforce_policy(&mut self, syscall_num: u64, args: &ArgMap) -> ConfineResult<i32> {
        if let Some(policy) = &self.policy {
            // get the syscall name
            let name: &str = match self.manager.get_syscall_name(syscall_num) {
                Some(name) => name,
                None => {
                    return Err(ConfineError::SystemError(NixError::invalid_argument()));
                }
            };

            log::debug!("Checking syscall `{}` against policy", name);

            // check if name is set as policy, and get enforcement
            if let Some(action) = policy.get_enforcement(&name) {
                match action {
                    // print warning with syscall but continue execution
                    Action::Warn => {
                        log::info!("confine: [WARN] encountered syscall {}", name);
                    }

                    // halt execution immediately and return
                    Action::Block => {
                        log::error!("confine: [BLOCK] encountered syscall {}", name);
                        return Ok(-1);
                    }

                    // write parsed syscall to log file
                    Action::Log => {
                        log::info!("Writing encountered syscall `{}` to log", name);
                        let parsed_syscall: ParsedSyscall =
                            ParsedSyscall::new(name.to_string(), args.clone());
                        policy.to_log(parsed_syscall)?;
                    }

                    // continue without issue
                    Action::Permit => {}
                }
            }
        }
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

        log::trace!("Checking numerical types");
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
        log::trace!("Checking for structs");
        if structs.iter().any(|&i| typename.contains(i)) || typename.contains("struct") {
            return Ok(json!(format!("0x{:x}", regval)));
        }

        // if a char buffer, use ptrace to read from address stored in register
        log::trace!("Checking for char buffers");
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

    /// Generates a dump of the trace excluding arguments and including varying capabilities
    /// for detecting potential IOCs
    pub fn threat_trace(&mut self) -> ConfineResult<String> {
        self.report.populate(&self.manager.0)?;
        let json = serde_json::to_string_pretty(&self.report)?;
        Ok(json)
    }
}
