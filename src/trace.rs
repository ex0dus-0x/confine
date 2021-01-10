//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use nix::Error as NixError;

use serde_json::{Value, json};
use unshare::{Command, Namespace};
use libc::user_regs_struct;

use std::io::Error as IOError;
use std::collections::HashMap;

use crate::syscall::SyscallManager;

// Helper wrapper over nix's ptrace TRACEME function, in order to ensure proper type conversion for
// its error type.
#[inline]
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
    pid: Pid,
    manager: SyscallManager,
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracer {
    pub fn new() -> Self {
        Self {
            pid: Pid::from_raw(-1),
            manager: SyscallManager::new().unwrap(),
        }
    }

    // TODO: implement `handle_rules()` to block system calls (or report them)
    //fn handle_rules(&mut self, rule_map)

    /// Runs a trace by forking child process, and uses parent to step through syscall events.
    pub fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, NixError> {
        // create new unshare-wrapped command with arguments
        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().skip(1) {
            cmd.arg(arg);
        }

        // initialize with unshared namespaces for container-like environment
        let namespaces = vec![Namespace::User, Namespace::Cgroup];
        cmd.unshare(&namespaces);

        // call traceme helper to signal parent for tracing
        unsafe {
            cmd.pre_exec(traceme);
        }

        // spawns a child process handler
        let child = match cmd.spawn() {
            Ok(handler) => handler,
            Err(_) => {
                return Err(NixError::last());
            }
        };

        // create nix Pid and set options before stepping
        let pid: Pid = Pid::from_raw(child.pid());
        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

        // save pid state for later use
        self.pid = pid;

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

        // once the system call manager is populated return
        Ok(self.manager.clone())
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
    fn parse_type(&mut self, typename: &str, regval: u64) -> Value {

        // return any type of numeric value without reading further
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
            return json!(regval);
        }

        // known aliases to structs
        // since parsing data structures is a lot of work, just store hex address
        let structs: Vec<&str> = vec![
            "cap_user_header_t",
            "cap_user_data_t",
            "siginfo_t",
            "aio_context_t",
        ];
        if structs.iter().any(|&i| typename.contains(i)) || typename.contains("struct") {
            return json!(format!("0x{:x}", regval));
        }

        // if a char buffer, use ptrace to read from address stored in register
        if typename.contains("char") {

            /* TODO
            // instantiate buffer to store contents from read
            let mut buffer: Vec<i64> = Vec::new();
            let mut val: i64 = -1;
            let mut cnt: u64 = 0;

            // loop until null terminating character
            while val != 48 {
                val = ptrace::read(self.pid, (regval + cnt) as *mut libc::c_void).unwrap();
                buffer.push(val);
                cnt += 2;
            }*/
            return json!(format!("0x{:x}", regval));
        }

        // default if type cannot be parsed out
        json!("UNKNOWN")
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
        // TODO: remove unwrap
        let to_read: Vec<String> = self.manager.get_arguments(syscall_num).unwrap();

        // for each argument, get corresponding register in calling convention, and parse
        // accordingly based on the given type
        let mut args: HashMap<String, Value> = HashMap::new();
        for (idx, arg) in to_read.iter().enumerate() {

            // get contents of register in calling convention by index
            let regval: u64 = Tracer::get_reg_idx(regstate, idx as i32);
            if regval == u64::MAX {
                panic!("proper error here")
            }

            // get type and decide if further reading is necessary
            let val: Value = self.parse_type(arg.as_str(), regval);

            // commit type and value mapping to hashmap
            args.insert(arg.to_string(), val);
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
}
