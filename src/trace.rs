//! Defines modes of operation for syscall and library tracing. Provides several interfaces and
//! wrappers to the `trace` submodule in order to allow convenient tracing.

use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::sys::wait;
use nix::unistd::Pid;

use unshare::{Command, Namespace};

use crate::error::TraceError;
use crate::syscall::SyscallManager;

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
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
            cmd.pre_exec(ptrace::traceme);
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
                reason: e,
            }
        })?;

        match wait::waitpid(Pid::from_raw(-1), None) {
            Ok(wait::WaitStatus::Stopped(pid, Signal::SIGUSR1)) => {
                let _ = ptrace::step(pid, None);
            },
            Err(e) => {
                return Err(TraceError::StepError {
                        pid: i32::from(pid),
                        reason: e.to_string(),
                    });
            },
            _ => {}
        }
        Ok(self.manager.clone())
    }

    /*
    /// Introspect single event in traced process, using ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<Option<c_int>, TraceError> {
        helpers::syscall(pid).map_err(|e| TraceError::PtraceError {
            call: "SYSCALL",
            reason: e,
        })?;

        if let Some(status) = self.wait() {
            return Ok(Some(status));
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
        //.map_err(SyscallError)?;

        helpers::syscall(pid).map_err(|e| TraceError::PtraceError {
            call: "SYSCALL",
            reason: e,
        })?;

        if let Some(status) = self.wait() {
            return Ok(Some(status));
        }
        Ok(None)
    }

    /// Libc wrapper to waitpid/wait4, with error-checking in order to return proper type back to developer.
    fn wait(&self) -> Option<c_int> {
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);

            // error-check status set
            if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status))
            } else {
                None
            }
        }
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

        /* TODO: register values for 32bit registers
        match reg {
            0 => regs::EBX,
            1 => regs::ECX,
            2 => regs::EDX,
            3 => regs::ESI,
            4 => regs::EDI,
            5 => regs::EBP,
            _ => panic!("Unmatched argument offset")
        }
        */

        let regval: i64 =
            helpers::peek_user(pid, offset).map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e,
            })?;
        Ok(regval as u64)
    }

    /// Use ptrace with PEEKTEXT in order to read out contents for a specified address.
    fn read_arg(&mut self, addr: u64) -> Result<u64, TraceError> {
        let argval: i64 =
            helpers::peek_text(pid, addr as usize).map_err(|e| TraceError::PtraceError {
                call: "PEEKTEXT",
                reason: e,
            })?;
        Ok(argval as u64)
    }

    /// Use ptrace with PEEKUSER to return the syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> Result<u64, TraceError> {
        let num: i64 =
            helpers::peek_user(pid, regs::ORIG_RAX).map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e,
            })?;
        Ok(num as u64)
    }
    */
}
