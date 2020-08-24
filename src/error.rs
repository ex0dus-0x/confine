//! Implements the error types used throughout the confine implementation whenever an exception is
//! encountered during runt

use std::error::Error;
use std::fmt::{self, Display};
use std::io::Error as IOError;

use libc::pid_t;

/// `SysManagerError` defines failures that can occur during system call parsing.
#[derive(Debug)]
pub enum SyscallError {
    IOError(IOError),
    UnsupportedSyscall { id: u64 },
    SyscallTableError { reason: &'static str },
}

impl Display for SyscallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "\"{:?}:\"", self)
    }
}

impl Error for SyscallError {}

/// Defines the different variants of errors encountered while tracing a process
#[derive(Debug)]
pub enum TraceError {
    SpawnError {
        reason: String,
    },
    StepError {
        pid: pid_t,
        reason: String,
    },
    PtraceError {
        call: &'static str,
        reason: IOError,
    },
    ProbeError {
        tracepoint: &'static str,
        reason: String,
    },
}

impl Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "\"{:?}:\"", self)
    }
}

impl Error for TraceError {}
