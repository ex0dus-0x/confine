//! policy.rs
//!
//!     Defines common confine policy format. Is used to then generate
//!     output configs for enforcers, or actual contained enforcement.

use std::{io, fs};
use std::boxed::Box;
use std::path::PathBuf;
use std::collections::HashMap;

use crate::syscall::Syscall;
use crate::enforcers::Enforcer;


/// declares an action parsed by the userspace application and applied to
/// system calls before trace.
enum SyscallState {
    Permitted,
    Warned,
    Unallowed
}


/// defines a policy hashmap where we initialize with default actions for
/// system calls
type PolicyMap = HashMap<Syscall, SyscallAction>;


impl Default for PolicyMap {

}


/// defines a parsed confine policy file
#[derive(Debug, Clone)]
pub struct Policy {
    path: PathBuf,
    enforcer: Box<Enforcer>,
    policy_map: PolicyMap,
}


impl Policy {

    /// `new_policy()` initializes a policy by parsing a TOML configuration into
    /// a serializable Policy struct.
    pub fn new_policy(path: PathBuf) -> io::Result<Self> {
        let policy_map = self.parse_policy(path);
        Ok(Self { path, enforcer, policy_map })
    }


    /// `parse_policy` reads in the syscall config section of a config, and parses it into an appropriate
    /// policy map for system calls with their configured actions
    fn parse_policy(&self, path) -> PolicyMap {

    }

}

