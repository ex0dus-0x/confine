//! Implements the error types used throughout the confine implementation whenever an exception is
//! encountered during runtime.

use std::error::Error;
use std::fmt::{self, Display};
use std::io::Error as IOError;

/// Defines failures that can occur during system call parsing.
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
