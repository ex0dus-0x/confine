//! mod.rs
//!
//!     Defines modes of operation for syscall and library tracing

pub mod ptrace;
pub mod ebpf;

use std::error::Error;

pub trait ProcessHandler {
    fn trace(pid: TraceProc) -> Result<(), Error>;
    fn output() -> ();
}

pub struct Ptrace;
pub struct Ebpf;

impl ProcessHandler for Ptrace {


}

impl ProcessHandler for Ebpf {


}
