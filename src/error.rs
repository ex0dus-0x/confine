//! Implements the error types used throughout the confine implementation whenever an exception is
//! encountered during runtime.
use nix::Error as NixError;
use serde_json::Error as JSONError;
use serde_yaml::Error as YAMLError;
//use unshare::Error as UnshareError;

use std::error::Error;
use std::fmt::{self, Display};
use std::io::Error as IOError;

/// Type alias to use to return custom error Type
pub type ConfineResult<T> = Result<T, ConfineError>;

/// Defines error encountered during confine trace execution
#[derive(Debug)]
pub enum ConfineError {
    // wraps over file I/O issues
    IOError(IOError),

    // problems encountered when attempting spawn a process
    //SpawnError(UnshareError),

    // problems encountered when attempting to call system facilities
    SystemError(NixError),

    // unable to parse and handle system calls
    SyscallError(String),

    // returned if de/serialization fails, specifies filetype
    ParseError(String),
}

impl Display for ConfineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfineError::IOError(..) => write!(f, "Failed to properly interact with file"),
            //ConfineError::SpawnError(err) => write!(f, "{}", err),
            ConfineError::SystemError(err) => write!(f, "Linux system error: {}", err),
            ConfineError::SyscallError(msg) => write!(f, "Error with handling syscalls: {}", msg),
            ConfineError::ParseError(err) => write!(f, "Unable to properly parse: {}", err),
        }
    }
}

impl Error for ConfineError {}

impl From<IOError> for ConfineError {
    fn from(err: IOError) -> ConfineError {
        ConfineError::IOError(err)
    }
}

/*
impl From<UnshareError> for ConfineError {
    fn from(err: UnshareError) -> ConfineError {
        ConfineError::SpawnError(err)
    }
}
*/

impl From<NixError> for ConfineError {
    fn from(err: NixError) -> ConfineError {
        ConfineError::SystemError(err)
    }
}

impl From<JSONError> for ConfineError {
    fn from(err: JSONError) -> ConfineError {
        ConfineError::ParseError(err.to_string())
    }
}

impl From<YAMLError> for ConfineError {
    fn from(err: YAMLError) -> ConfineError {
        ConfineError::ParseError(err.to_string())
    }
}
