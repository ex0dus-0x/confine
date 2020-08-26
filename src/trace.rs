//! Defines modes of operation for syscall and library tracing.
//! Provides several interfaces and wrappers to the `trace` submodule
//! in order to allow convenient tracing.

use libc::{c_int, pid_t};
use unshare::Command;
use unshare::Namespace;

use crate::error::{SyscallError, TraceError};
use crate::ptrace::consts::{options, regs};
use crate::ptrace::helpers;
use crate::syscall::SyscallManager;

/// Wrapper interface for ptrace tracing. Enforces various methods around important
/// syscalls and libc calls that allows convenient tracer/tracee process interactions.
pub struct Tracer {
    pid: pid_t,
    manager: SyscallManager,
}

impl Default for Tracer {
    fn default() -> Self {
        Self {
            pid: 0,
            manager: SyscallManager::new(),
        }
    }
}

impl Tracer {
    pub fn new() -> Self {
        Self::default()
    }

    // TODO: implement `handle_rules()` to block system calls (or report them)
    //fn handle_rules(&mut self, rule_map)

    /// `trace()` functionality for ptrace mode. Forks a child process, and uses parent to
    /// to step through syscall events.
    pub fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, TraceError> {
        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().next() {
            cmd.arg(arg);
        }

        // initialize with unshared namespaces for container-like environment
        let namespaces = vec![Namespace::User, Namespace::Cgroup];
        cmd.unshare(&namespaces);

        // call traceme helper to signal parent for tracing
        cmd.before_exec(helpers::traceme);

        // spawns a child process handler
        let child = match cmd.spawn() {
            Ok(handler) => handler,
            Err(_) => {
                return Err(TraceError::SpawnError {
                    reason: "Failed to spawn child process".to_string(),
                });
            }
        };

        // retrieve spawned child process ID and store for tracer routines
        self.pid = child.pid();

        helpers::set_options(self.pid, options::PTRACE_O_TRACESYSGOOD as usize).map_err(|e| {
            TraceError::PtraceError {
                call: "SETOPTIONS",
                reason: e,
            }
        })?;

        // execute loop that examines through syscalls
        loop {
            match self.step() {
                Ok(Some(status)) => {
                    if status == 0 {
                        break;
                    } else {
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(TraceError::StepError {
                        pid: self.pid,
                        reason: e.to_string(),
                    });
                }
            }
        }
        Ok(self.manager.clone())
    }

    /// `step()` defines the main introspection performed ontop of the traced process, using
    /// ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<Option<c_int>, TraceError> {
        helpers::syscall(self.pid).map_err(|e| TraceError::PtraceError {
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
        for i in 0..3 {
            let _arg = self.get_arg(i)?;
            let arg = self.read_arg(_arg)?;
            args.push(arg);
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args).unwrap();
        //.map_err(SyscallError)?;

        helpers::syscall(self.pid).map_err(|e| TraceError::PtraceError {
            call: "SYSCALL",
            reason: e,
        })?;

        if let Some(status) = self.wait() {
            return Ok(Some(status));
        }
        Ok(None)
    }

    /// `wait()` wrapper to waitpid/wait4, with error-checking in order to return proper type back to developer.
    fn wait(&self) -> Option<c_int> {
        let mut status = 0;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);

            // error-check status set
            if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status))
            } else {
                None
            }
        }
    }

    /// `get_arg()` is called to introspect current process states register values in order to determine syscall
    /// and arguments passed.
    fn get_arg(&mut self, reg: u8) -> Result<u64, TraceError> {
        #[cfg(target_arch = "x86_64")]
        let offset = if cfg!(target_arch = "x86_64") {
            match reg {
                0 => regs::RDI,
                1 => regs::RSI,
                2 => regs::RDX,
                3 => regs::RCX,
                4 => regs::R8,
                5 => regs::R9,
                _ => panic!("Unmatched argument offset"),
            }
        } else {
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
            unimplemented!()
        };

        let regval: i64 = helpers::peek_user(self.pid, offset)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e,
            })?;
        Ok(regval as u64)
    }

    /// `read_arg()` uses ptrace with PEEKTEXT in order to read out contents for a specified address.
    fn read_arg(&mut self, addr: u64) -> Result<u64, TraceError> {
        helpers::peek_text(self.pid, addr as usize)
            .map(|x| x as u64)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKTEXT",
                reason: e,
            })
    }

    /// `get_syscall_num()` uses ptrace with PEEKUSER to return the syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> Result<u64, TraceError> {
        helpers::peek_user(self.pid, regs::ORIG_RAX)
            .map(|x| x as u64)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER",
                reason: e,
            })
    }
}
