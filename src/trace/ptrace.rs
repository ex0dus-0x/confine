//! ptrace.rs
//!
//!     Currently, `nix` support for `ptrace(2)` on the most recent
//!     version of the crate (as of working, 0.12.0) is deprecated.
//!     This is a re-implementation of `ptrace(2)` that allows safer
//!     usage through a specialized helper function.

#![allow(dead_code)]
pub mod consts {

    /// these represent `PtraceRequest`s a tracer
    /// can send to tracee in order to perform actions
    /// on attached process.
    pub mod requests {
        use libc::c_int;

        /// while the parameters of `ptrace(2)` call for
        /// a `enum __ptrace_request`, we simplify it for FFI
        /// and instead define as an alias to a C integer.
        type PtraceRequest = c_int;

        pub const PTRACE_TRACEME:     PtraceRequest = 0;
        pub const PTRACE_PEEKTEXT:    PtraceRequest = 1;
        pub const PTRACE_PEEKDATA:    PtraceRequest = 2;
        pub const PTRACE_PEEKUSER:    PtraceRequest = 3;
        pub const PTRACE_POKETEXT:    PtraceRequest = 4;
        pub const PTRACE_POKEDATA:    PtraceRequest = 5;
        pub const PTRACE_POKEUSER:    PtraceRequest = 6;
        pub const PTRACE_CONT:        PtraceRequest = 7;
        pub const PTRACE_KILL:        PtraceRequest = 8;
        pub const PTRACE_SINGLESTEP:  PtraceRequest = 9;
        pub const PTRACE_GETREGS:     PtraceRequest = 12;
        pub const PTRACE_SETREGS:     PtraceRequest = 13;
        pub const PTRACE_GETFPREGS:   PtraceRequest = 14;
        pub const PTRACE_SETFPREGS:   PtraceRequest = 15;
        pub const PTRACE_ATTACH:      PtraceRequest = 16;
        pub const PTRACE_DETACH:      PtraceRequest = 17;
        pub const PTRACE_GETFPXREGS:  PtraceRequest = 18;
        pub const PTRACE_SETFPXREGS:  PtraceRequest = 19;
        pub const PTRACE_SYSCALL:     PtraceRequest = 24;
        pub const PTRACE_SETOPTIONS:  PtraceRequest = 0x4200;
        pub const PTRACE_GETEVENTMSG: PtraceRequest = 0x4201;
        pub const PTRACE_GETSIGINFO:  PtraceRequest = 0x4202;
        pub const PTRACE_SETSIGINFO:  PtraceRequest = 0x4203;
        pub const PTRACE_GETREGSET:   PtraceRequest = 0x4204;
        pub const PTRACE_SETREGSET:   PtraceRequest = 0x4205;
        pub const PTRACE_SEIZE:       PtraceRequest = 0x4206;
        pub const PTRACE_INTERRUPT:   PtraceRequest = 0x4207;
        pub const PTRACE_LISTEN:      PtraceRequest = 0x4208;
        pub const PTRACE_PEEKSIGINFO: PtraceRequest = 0x4209;
    }

    pub mod options {
        use libc::c_int;

        /// represents constants to be used for the `data`
        /// parameter when calling ptrace with PTRACE_SETOPTIONS
        type PtraceOption = c_int;

	pub const PTRACE_O_TRACESYSGOOD:   PtraceOption = 0x01;
        pub const PTRACE_O_TRACEFORK:	   PtraceOption = 0x02;
        pub const PTRACE_O_TRACEVFORK:	   PtraceOption = 0x03;
        pub const PTRACE_O_TRACECLONE:	   PtraceOption = 0x04;
        pub const PTRACE_O_TRACEEXEC:	   PtraceOption = 0x05;
        pub const PTRACE_O_TRACEVFORKDONE: PtraceOption = 0x06;
        pub const PTRACE_O_TRACEEXIT: 	   PtraceOption = 0x07;
	pub const PTRACE_O_TRACESECCOMP:   PtraceOption = 0x08;
    }


    pub mod regs {

	/// i64 represents value register value
	type RegVal = i64;

        pub const R15:		   RegVal = 0 * 8;
        pub const R14:		   RegVal = 1 * 8;
        pub const R13:		   RegVal = 2 * 8;
        pub const R12:		   RegVal = 3 * 8;
        pub const RBP:		   RegVal = 4 * 8;
        pub const RBX:		   RegVal = 5 * 8;
        pub const R11:		   RegVal = 6 * 8;
        pub const R10:		   RegVal = 7 * 8;
        pub const R9:		   RegVal = 8 * 8;
        pub const R8:		   RegVal = 9 * 8;

        pub const RAX:		   RegVal = 10 * 8;
        pub const RCX:		   RegVal = 11 * 8;
        pub const RDX:		   RegVal = 12 * 8;
        pub const RSI:		   RegVal = 13 * 8;
        pub const RDI:		   RegVal = 14 * 8;
        pub const ORIG_RAX:    RegVal = 15 * 8;
        pub const RIP: 		   u64    = 16 * 8;

        pub const CS: 		   RegVal = 17 * 8;
        pub const EFLAGS: 	   RegVal = 18 * 8;
        pub const RSP: 		   RegVal = 19 * 8;
        pub const SS: 		   RegVal = 20 * 8;
        pub const FS_BASE: 	   RegVal = 21 * 8;
        pub const GS_BASE: 	   RegVal = 22 * 8;
        pub const DS:		   RegVal = 23 * 8;
        pub const ES:		   RegVal = 24 * 8;
        pub const FS:		   RegVal = 25 * 8;
	pub const GS:		   RegVal = 26 * 8;
    }
}


mod ptrace {
    use libc::{c_int, c_long, c_void, pid_t};
    use nix::errno::Errno;


    /// defines an `unsafe` foreign function interface to the `ptrace(2)` system call.
    /// `ptrace(2)`'s original C function definition is as follows:
    ///
    /// ```
    ///     long ptrace(enum __ptrace_request request, pid_t pid,
    ///                 void *addr, void *data);
    /// ```
    extern {
        fn ptrace(request: c_int, pid: pid_t,
                  addr: * const c_void, data: * const c_void) -> c_long;
    }


    /// `exec_ptrace()` is the main and safest interface for calling the unsafe `ptrace` FFI.
    /// It does error-checking to ensure that the user receives errors through Result<T>, and
    pub fn exec_ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> Result<i64, Errno> {
        use super::consts::requests;

        // on PTRACE_PEEK* commands, a successful request might still return -1. As a result,
        // we need to clear errno and do some other error-checking.
        match request {
            requests::PTRACE_PEEKTEXT | requests::PTRACE_PEEKDATA | requests::PTRACE_PEEKUSER => {

                // grab return value of ptrace call (notice no semicolon)
                let ret = unsafe {
                    Errno::clear();
                    ptrace(request, pid, addr, data)
                };

                // error-check and ensure that errno is actually not a false positive
                if (ret == -1) && (Errno::last() != Errno::UnknownErrno) {
                    return Err(Errno::last());
                }
                return Ok(ret);
            },
            _ => {},
        }

        // for other conventional PTRACE_* commands
        match unsafe { ptrace(request, pid, addr, data) } {
            -1 => Err(Errno::last()),
            _ => Ok(0)
        }
    }
}



/// defines helper functions that interact with `exec_ptrace`
/// in order to perform process debugging.
pub mod helpers {
    use std::{ptr, mem};
    use std::io::{Error, ErrorKind};
    use libc::pid_t;

    use super::{consts, ptrace};


    /// alias the pid_t for better clarification
    type InferiorType = pid_t;

    /// alias a null pointer type for ptrace type parameter
    const NULL: *mut libc::c_void = ptr::null_mut();


    /// `traceme()` call with error-checking. PTRACE_TRACEME is used as a method
    /// used to check the process that the user is currently in, such as ensuring that
    /// a fork call actually spawned off a child process.
    pub fn traceme() -> Result<(), Error> {
        if let Err(e) = ptrace::exec_ptrace(consts::requests::PTRACE_TRACEME, 0, NULL, NULL) {
            let err = Error::new(ErrorKind::Other, e.desc());
            return Err(err);
        }
        Ok(())
    }


    /// `syscall()` call with error-checking. PTRACE_SYSCALL is used when tracer steps through
    /// syscall entry/exit in trace, and enables debugging process to perform further introspection.
    pub fn syscall(pid: InferiorType) -> Result<i64, Error> {
        match ptrace::exec_ptrace(consts::requests::PTRACE_SYSCALL, pid, NULL, NULL) {
            Err(e) => {
                let err = Error::new(ErrorKind::Other, e.desc());
                Err(err)
            },
            Ok(res) => Ok(res)
        }
    }


    /// `peek_user()` call with error-checking. PTRACE_PEEKUSER is used in order to
    /// introspect register values when encountering SYSCALL_ENTER or SYSCALL_EXIT.
    pub fn peek_user(pid: InferiorType, register: i64) -> Result<i64, Error> {
        match ptrace::exec_ptrace(consts::requests::PTRACE_PEEKUSER, pid, register as *mut libc::c_void, NULL){
            Err(e) => {
                let err = Error::new(ErrorKind::Other, e.desc());
                Err(err)
            },
            Ok(res) => Ok(res)
        }
    }


    /// `get_regs()` call with error-checking. PTRACE_GETREGS is used in order to
    /// get and store the currently set register state. The wrapper actually returns this back to
    /// the developer in a struct.
    pub fn get_regs(pid: InferiorType) -> Result<libc::user_regs_struct, Error> {
        unsafe {

            // initialize uninitialized memory for register struct
            let regs: libc::user_regs_struct = mem::uninitialized();

            // cast user_regs_struct to c_void using mem::transmute_copy
            if let Err(e) = ptrace::exec_ptrace(consts::requests::PTRACE_GETREGS, pid, NULL,
                                                mem::transmute_copy::<libc::user_regs_struct, *mut libc::c_void>(&regs)) {
                let err = Error::new(ErrorKind::Other, e.desc());
                return Err(err);
            }
            Ok(regs)
        }
    }


    /// `set_options()` called with error-checking. PTRACE_SETOPTIONS is called,
    /// with flag options set by users.
    pub fn set_options(pid: InferiorType, options: i64) -> Result<(), Error> {
        if let Err(e) = ptrace::exec_ptrace(consts::requests::PTRACE_SETOPTIONS, pid, NULL, options as *mut libc::c_void) {
            let err = Error::new(ErrorKind::Other, e.desc());
            return Err(err);
        }
        Ok(())
    }
}
