//! seccomp.rs
//!
//!     Defines the Docker seccomp enforcer module. Implements the custom
//!     enforcer trait in order to convert and export common policies.

use std::enforcers::Enforcer;


/// `Seccomp` interface that encapsulates the file structure for a
/// JSON-based seccomp policy for Docker.
#[derive(Serialize)]
pub struct Seccomp {
    default_action: String,
    syscalls: Vec<SeccompSyscall>
}


struct SeccompSyscall {
    names: Vec<String>,
    action: String,
    args: Vec<String>,
    comment: String,
}

struct SeccompArg {
    index: i32,
    value: u64,
    valueTwo: i32,
    op: String
}


impl Enforcer for Seccomp {
    fn from_policy(policy: PolicyInterface) -> Self {


    }


    fn output_policy(&self) -> &'static str {


    }
}
