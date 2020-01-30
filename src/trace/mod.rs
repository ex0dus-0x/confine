//! mod.rs
//!
//!     Defines modes of operation for syscall and library tracing.
//!     Provides several interfaces and wrappers to the `trace` submodule
//!     in order to allow convenient tracing.

use libc::{pid_t, c_int};

use unshare::Command;
use unshare::Namespace;

use bcc::core::BPF;
use bcc::perf;

use crate::syscall::{SyscallError, SyscallManager};

use failure::Error as FailError;
use std::io::Error as IOError;

pub mod ptrace;
use self::ptrace::helpers;
use self::ptrace::consts::{options, regs};


#[derive(Debug, Fail)]
pub enum TraceError {

    #[fail(display = "Could not interact with syscall manager.")]
    ManagerError(SyscallError),

    #[fail(display = "Could not spawn child tracee process. Reason: {}", reason)]
    SpawnError { reason: String },

    #[fail(display = "Could not step through child PID {}. Reason: {}", pid, reason)]
    StepError { pid: pid_t, reason: String },

    #[fail(display = "PTRACE_{} failed with error `{}`", call, reason)]
    PtraceError { call: &'static str, reason: IOError },

    #[fail(display = "Could not initialize BPF source. Reason: {}", reason)]
    BPFError { reason: FailError },

    #[fail(display = "Could not attach kprobe to tracepoint {}. Reason: {}", tracepoint, reason)]
    ProbeError { tracepoint: &'static str, reason: FailError },
}


/// trait that handles support for extending tracing support
/// for various modes. Wraps around our tracing mode of operations.
pub trait ProcessHandler {

    // initializes a new interface that implements the ProcessHandler trait
    fn new() -> Self where Self: Sized;

    // handle calls with the appropriate trace method based on rules implemented
    //fn handle_rules() -> Result<(), TraceError>

    // runs the appropriate trace method with arguments to the program
    fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, TraceError>;
}


/// wrapper interface for ebpf tracing. Contains methods for dynamic ebpf code generation
/// for rust bcc bindings, and attaching hooks to read and parse syscall events.
pub struct Ebpf {
    manager: SyscallManager
}

impl ProcessHandler for Ebpf {

    fn new() -> Self {
        Self { manager: SyscallManager::new() }
    }


    /// the `trace()` implementation for eBPF first instantiates from a source template,
    /// and attaches a callback that reads syscall events from a perf map that parsed out
    /// various components of a system call.
    fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, TraceError> {

        let code = include_str!("ebpf/template.c");

        // TODO: generate source per syscall

        // initialize new BPF module
        let mut module: BPF = BPF::new(code).map_err(|e| {
            TraceError::BPFError { reason: e }
        })?;


        // attach kprobe and kretprobe on system calls
        for (_, syscall) in self.manager.syscall_table.iter() {

            // initialize a kprobe at the event of entering a syscall
            let entry_probe = match module.load_kprobe("trace_entry") {
                Ok(probe) => probe,
                Err(e) => {
                    return Err(TraceError::ProbeError { tracepoint: "trace_entry", reason: e });
                }
            };

            // initialize probe at event of syscall finishing execution
            let ret_probe = match module.load_kprobe("trace_return") {
                Ok(probe) => probe,
                Err(e) => {
                    return Err(TraceError::ProbeError { tracepoint: "trace_return", reason: e });
                }
            };

            let event = &format!("do_sys_{}", syscall);

            if let Err(e) = module.attach_kprobe(event, entry_probe) {
                return Err(TraceError::BPFError { reason: e });
            }

            if let Err(e) = module.attach_kretprobe(event, ret_probe) {
                return Err(TraceError::BPFError { reason: e });
            }
        }

        let table = module.table("events");
        let mut perf_map = perf::init_perf_map(table, Ebpf::perf_callback).map_err(|e| {
            TraceError::BPFError { reason: e }
        })?;

        // TODO: break after a duration of execution, otherwise function doesn't return
        loop {
            perf_map.poll(200);
        }

        Ok(self.manager.clone())
    }
}


impl Ebpf {

    /// `perf_callback` is a callback routine invoked by bcc when encountering syscall events. Reads and parses
    /// a structure that encapsulates a system call, and outputs accordingly to a syscall manager.
    /// TODO
    #[inline]
    fn perf_callback() -> Box<FnMut(&[u8]) + Send> {
        Box::new(|_| {

        })
    }
}


/// wrapper interface for ptrace tracing. Enforces various methods around important
/// syscalls and libc calls that allows convenient tracer/tracee process interactions.
pub struct Ptrace {
    pid: pid_t,
    manager: SyscallManager
}


impl ProcessHandler for Ptrace {

    fn new() -> Self {
        Self { pid: 0, manager: SyscallManager::new() }
    }

    // TODO: implement `handle_rules()` to block system calls (or report them)


    /// `trace()` functionality for ptrace mode. Forks a child process, and uses parent to
    /// to step through syscall events.
    fn trace(&mut self, args: Vec<String>) -> Result<SyscallManager, TraceError> {

        let mut cmd = Command::new(&args[0]);
        for arg in args.iter().next() {
            cmd.arg(arg);
        }

        // initialize with unshared namespaces for container-like environment
        let namespaces = vec![Namespace::Pid, Namespace::User, Namespace::Cgroup];
        cmd.unshare(&namespaces);

        // call traceme helper to signal parent for tracing
        cmd.before_exec(helpers::traceme);

        // spawns a child process handler
        info!("Initializing child process and calling PTRACE_TRACEME");
        let child = match cmd.spawn() {
            Ok(handler) => handler,
            Err(e) => {
                return Err(TraceError::SpawnError { reason: e.to_string() });
            }
        };

        // retrieve spawned child process ID and store for tracer routines
        self.pid = child.pid();
        debug!("Child PID: {}", self.pid);

        info!("Setting trace options with PTRACE_SETOPTIONS");
        helpers::set_options(self.pid, options::PTRACE_O_TRACESYSGOOD.into())
            .map_err(|e| TraceError::PtraceError {
                call: "SETOPTIONS", reason: e
            })?;


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
                Err(e) => {
                    return Err(TraceError::StepError { pid: self.pid, reason: e.to_string() });
                },
            }
        }
        Ok(self.manager.clone())
     }
}


impl Ptrace {

    /// `step()` defines the main instrospection performed ontop of the traced process, using
    /// ptrace to parse out syscall registers for output.
    fn step(&mut self) -> Result<Option<c_int>, TraceError> {

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_ENTER");
        helpers::syscall(self.pid)
            .map_err(|e| TraceError::PtraceError {
                call: "SYSCALL", reason: e
            })?;

        if let Some(status) = self.wait() {
            return Ok(Some(status));
        }

        // determine syscall number and initialize
        let syscall_num = self.get_syscall_num()?;
        debug!("Syscall number: {:?}", syscall_num);

        // retrieve first 3 arguments from syscall
        let mut args: Vec<u64> = Vec::new();
        for i in 0..3 {
            let _arg = self.get_arg(i)?;
            let arg = self.read_arg(_arg)?;
            args.push(arg);
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args).map_err(TraceError::ManagerError)?;

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_EXIT");
        helpers::syscall(self.pid)
            .map_err(|e| TraceError::PtraceError {
                call: "SYSCALL", reason: e
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
            0 => regs::EBX,
            1 => regs::ECX,
            2 => regs::EDX,
            3 => regs::ESI,
            4 => regs::EDI,
            5 => regs::EBP,
            _ => panic!("Unmatched argument offset")
        };
        */
        helpers::peek_user(self.pid, offset)
            .map(|x| x as u64)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER", reason: e
            })
    }


    /// `read_arg()` uses ptrace with PEEKTEXT in order to read out contents for a specified address.
    fn read_arg(&mut self, addr: u64) -> Result<u64, TraceError> {
        helpers::peek_text(self.pid, addr as i64)
            .map(|x| x as u64)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKTEXT", reason: e
            })
    }


    /// `get_syscall_num()` uses ptrace with PEEKUSER to return the syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> Result<u64, TraceError> {
        helpers::peek_user(self.pid, regs::ORIG_RAX)
            .map(|x| x as u64)
            .map_err(|e| TraceError::PtraceError {
                call: "PEEKUSER", reason: e
            })
    }
}
