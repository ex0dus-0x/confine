//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.

use nix::sys::ptrace::{self, Options};
use nix::sys::wait;
use nix::unistd::Pid;

use unshare::{Command, Namespace};

use crate::error::TraceError;
use crate::syscall::SyscallManager;

use std::io::{Error, ErrorKind};


// Helper wrapper over nix's ptrace TRACEME function, in order to ensure proper type conversion for
// its error type.
#[inline]
fn traceme() -> Result<(), Error> {
    match ptrace::traceme() {
        Err(nix::Error::Sys(errno)) => Err(Error::from_raw_os_error(errno as i32)),
        Err(e) => Err(Error::new(ErrorKind::Other, e)),
        _ => Ok(())
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
            manager: SyscallManager::new(),
        }
    }

    // TODO: implement `handle_rules()` to block system calls (or report them)
    //fn handle_rules(&mut self, rule_map)

    /// Runs a trace by forking child process, and uses parent to step through syscall events.
    pub fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, TraceError> {
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
                return Err(TraceError::SpawnError {
                    reason: "Failed to spawn child process".to_string(),
                });
            }
        };

        // create nix Pid and set options before stepping
        let pid: Pid = Pid::from_raw(child.pid());
        ptrace::setoptions(pid, Options::PTRACE_O_TRACESYSGOOD).map_err(|e| {
            TraceError::PtraceError {
                call: "SETOPTIONS",
                reason: e.to_string(),
            }
        })?;

        // save pid state for later use
        self.pid = pid;

        // wait for process to change execution state
        match wait::waitpid(self.pid, None) {
            Err(e) => {
                return Err(TraceError::StepError {
                        pid: i32::from(self.pid),
                        reason: e.to_string(),
                    });
            },
            _ => {}
        }

        // run loop until broken by end of execution
        loop {
            match self.step() {
                Ok(Some(status)) => {
                    // break if successfully completed execution
                    if status == 0 { break; }
                },
                Err(e) => {
                    return Err(e);
                },
                _ => {}
            }
        }

        // once the system call manager is populated return
        Ok(self.manager.clone())
    }


    /// Introspect single event in traced process, using ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<Option<i32>, TraceError> {

        // encounter SYSCALL_ENTER
        ptrace::syscall(self.pid, None).map_err(|e| TraceError::PtraceError {
            call: "SYSCALL",
            reason: e.to_string(),
        })?;


        // wait for status, return status if finished execution
        match wait::waitpid(self.pid, None) {
            Ok(status) => {
                if let wait::WaitStatus::Exited(_, stat) = status {
                    return Ok(Some(stat));
                } else {
                    return Ok(None);
                }
            },
            Err(e) => {
                return Err(TraceError::StepError {
                    pid: i32::from(self.pid),
                    reason: e.to_string(),
                });
            },
            _ => {}
        }

        // determine syscall number and initialize
        let syscall_num = self.get_syscall_num()?;

        // retrieve first 3 arguments from syscall
        let mut args: Vec<u64> = Vec::new();
        for i in 0..2 {
            let _arg = self.get_arg(i)?;
            //let arg = self.read_arg(_arg)?;
            args.push(_arg);
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args).unwrap();

        // encounter SYSCALL_EXIT
        ptrace::syscall(self.pid, None).map_err(|e| TraceError::PtraceError {
            call: "SYSCALL",
            reason: e.to_string(),
        })?;

        // wait for status, return status if finished execution
        match wait::waitpid(self.pid, None) {
            Ok(status) => {
                if let wait::WaitStatus::Exited(_, stat) = status {
                    return Ok(Some(stat));
                } else {
                    return Ok(None);
                }
            },
            Err(e) => {
                return Err(TraceError::StepError {
                    pid: i32::from(self.pid),
                    reason: e.to_string(),
                });
            },
            _ => {}
        }

        Ok(None)
    }

    /// Introspect current process states register values in order to determine syscall and arguments passed.
    fn get_arg(&mut self, reg: u8) -> Result<u64, TraceError> {
        #[cfg(target_arch = "x86_64")]
        let offset = match reg {
            0 => regs::RDI,
            1 => regs::RSI,
            2 => regs::RDX,
            3 => regs::RCX,
            4 => regs::R8,
            5 => regs::R9,
            _ => panic!("Unmatched argument offset"),
        };

        let regval: i64 =
            helpers::peek_user(self.pid, offset).map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e.to_string(),
            })?;
        Ok(regval as u64)
    }

    /// Use ptrace with PEEKTEXT in order to read out contents for a specified address.
    fn read_arg(&mut self, addr: u64) -> Result<u64, TraceError> {
        let argval: i64 =
            helpers::peek_text(pid, addr as usize).map_err(|e| TraceError::PtraceError {
                call: "PEEKTEXT",
                reason: e.to_string(),
            })?;
        Ok(argval as u64)
    }

    /// Use ptrace with PEEKUSER to return the syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> Result<u64, TraceError> {
        let num: i64 =
            helpers::peek_user(pid, regs::ORIG_RAX).map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e.to_string(),
            })?;
        Ok(num as u64)
    }
}
