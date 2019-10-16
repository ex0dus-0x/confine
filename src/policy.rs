//! policy.rs
//!
//!     Defines common confine policy format. Is used to then generate
//!     output configs for enforcers, or actual contained enforcement.

use std::path::PathBuf;

use crate::syscall::Syscall;


/// defines a parsed confine policy file
#[derive(Debug, Clone)]
pub struct Policy {
    file: PathBuf,
}


impl Policy {

    /// `new_policy()` initializes a policy by parsing a TOML configuration into
    /// a serializable Policy struct.
    pub fn new_policy(path: PathBuf) -> Self {
        Self {
            file: path,
        }
    }
}
