//! mod.rs
//!
//!     Defines modes of operation for syscall and library tracing.
//!     Provides several interfaces and wrappers to the `trace` submodule
//!     in order to allow convenient tracing.

use libc::{pid_t, c_int};
use nix::unistd;
use nix::sys::signal;

use failure::Error;

use std::io;
use std::ffi::CString;
use std::process::Command;

use crate::syscall::SyscallManager;

pub mod ptrace;
use self::ptrace::helpers;
use self::ptrace::consts::{options, regs};


#[derive(Debug, Fail)]
pub enum TraceError {

    #[fail(display = "Cannot execute trace for {} mode. Reason: {}", mode, reason)]
    ExecError { mode: String, reason: String }

}


/// trait that handles support for extending tracing support
/// for various modes. Wraps around our tracing mode of operations.
pub trait ProcessHandler {
    fn new() -> Self where Self: Sized;
    fn trace(&mut self, cmd: Command, args: Vec<String>) -> Result<SyscallManager, Error>;
}


/// wrapper interface for ebpf tracing. Contains methods for dynamic ebpf code generation
/// for rust bcc bindings, and attaching hooks to read and parse syscall events.
pub struct Ebpf {
    manager: SyscallManager
}

// TODO
impl ProcessHandler for Ebpf {

    fn new() -> Self {
        Self {
            manager: SyscallManager::new()
        }
    }

    fn trace(&mut self, cmd: Command, args: Vec<String>) -> Result<SyscallManager, Error> {
        Ok(self.manager.clone())
    }
}


/// wrapper interface for ptrace tracing. Enforces various methods around important
/// syscalls and libc calls that allows convenient tracer/tracee process interactions.
pub struct Ptrace {
    pid: pid_t,
    manager: SyscallManager
}


impl ProcessHandler for Ptrace {

    /// `new()` simply initializes a trace handler with a syscall manager for r/w
    fn new() -> Self {
        Self {
            pid: 0,
            manager: SyscallManager::new()
        }
    }

    /// `trace()` functionality for ptrace mode. Forks a child process, and uses parent to
    /// to step through syscall events.
    fn trace(&mut self, cmd: Command, args: Vec<String>) -> Result<SyscallManager, Error> {
        info!("Forking child process from parent");
        let result = unistd::fork().expect("unable to call fork(2)");
        match result {
            unistd::ForkResult::Parent { child } => {

                info!("Tracing parent process");
                self.pid = child.as_raw();

                // in parent, wait for process event from child
                info!("Waiting for child process to send SIGSTOP");
                self.wait()?;

                // set trace options
                info!("Setting trace options with PTRACE_SETOPTIONS");
                helpers::set_options(child.as_raw(), options::PTRACE_O_TRACESYSGOOD.into());

                // execute loop that examines through syscalls
                info!("Executing parent with tracing");
                loop {
                    match self.step() {
                        Ok(Some(status)) => {
                            if status == 0 {
                                break;
                            } else {
                                debug!("Status reported: {:?}", status);
                            }
                        },
                        Ok(None) => {},
                        Err(e) => { return Err(e); },
                    }
                }
            },
            unistd::ForkResult::Child => {
                info!("Tracing child process");

                // start tracing process, notifying parent through wait(2)
                info!("Child process executing PTRACE_TRACEME");
                helpers::traceme();

                // send a SIGSTOP in order to stop child process for parent introspection
                info!("Sending SIGTRAP, going back to parent process");
                signal::kill(unistd::getpid(), signal::Signal::SIGSTOP);

                // execute child process with tracing until termination
                info!("Executing rest of child execution until termination");
                let c_cmd = CString::new(args[0].clone()).expect("failed to initialize CString command");
                let c_args: Vec<CString> = args.iter()
                    .map(|arg| CString::new(arg.as_str()).expect("CString::new() failed"))
                    .collect();
                unistd::execvp(&c_cmd, &c_args).ok().expect("failed to call execvp(2) in child process");
            }
        }
        Ok(self.manager.clone())
    }
}

impl Ptrace {

    /// `step()` defines the main instrospection performed ontop of the traced process, using
    /// ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<Option<c_int>, Error> {

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_ENTER");
        helpers::syscall(self.pid)?;
        if let Some(status) = self.wait()? {
            return Ok(Some(status));
        }

        // determine syscall number and initialize
        let syscall_num = match self.get_syscall_num() {
            Ok(num) => num,
            Err(e) => panic!("Cannot retrieve syscall number. Reason {:?}", e),
        };
        debug!("Syscall number: {:?}", syscall_num);

        // retrieve first 3 arguments from syscall
        let mut args: Vec<u64> = Vec::new();
        for i in 0..2 {
            args.push(self.get_arg(i)?);
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args);

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_EXIT");
        helpers::syscall(self.pid)?;
        if let Some(status) = self.wait()? {
            return Ok(Some(status));
        }
        Ok(None)
    }


    /// `wait()` wrapper to waitpid/wait4, with error-checking in order
    /// to return proper type back to developer.
    fn wait(&self) -> io::Result<Option<c_int>> {
        let mut status = 0;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);

            // error-check status set
            if libc::WIFEXITED(status) {
                Ok(Some(libc::WEXITSTATUS(status)))
            } else {
                Ok(None)
            }
        }
    }


    /// `get_arg()` is called to introspect current process
    /// states register values in order to determine syscall
    /// and arguments passed.
    fn get_arg(&mut self, reg: u8) -> io::Result<u64> {

        #[cfg(target_arch = "x86_64")]
        let offset = match reg {
            0 => regs::RDI,
            1 => regs::RSI,
            2 => regs::RDX,
            3 => regs::RCX,
            4 => regs::R8,
            5 => regs::R9,
            _ => panic!("Unmatched argument offset")
        };

        /* TODO: implement registers for 32-bit binaries
        #[cfg(target_arch = "x86")]
        let offset = match reg {
            0 => regs::EDI,
            1 => regs::ESI,
            2 => regs::EDX,
            3 => regs::ECX,
            4 => regs::E8,
            5 => regs::E9,
            _ => panic!("Unmatched argument offset")
        };
        */
        helpers::peek_user(self.pid, offset).map(|x| x as u64)
    }


    /// `get_syscall_num()` uses ptrace with PEEK_USER to return the
    /// syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> io::Result<u64> {
        helpers::peek_user(self.pid, regs::ORIG_RAX).map(|x| x as u64)
    }
}
