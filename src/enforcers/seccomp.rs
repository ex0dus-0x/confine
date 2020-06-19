//! Defines the Docker seccomp enforcer module. Implements the custom
//! enforcer trait in order to convert and export common policies.

use std::enforcers::Enforcer;


/// `Seccomp` interface that encapsulates the file structure for a
/// JSON-based seccomp policy for Docker.
#[derive(Serialize)]
pub struct Seccomp {
    default_action: String,
    architectures: Vec<String>,
    syscalls: Vec<SeccompSyscall>
}


/// `SeccompSyscall` represents a rule that is enforced by the container
/// for a specific system call.
struct SeccompSyscall {
    names: Vec<String>,
    action: String,
    args: Vec<String>,
    comment: String,
}


impl Enforcer for Seccomp {
    fn from_policy(policy: PolicyInterface) -> Self {
        unimplemented!();
    }


    fn output_policy(&self) -> &'static str {
        unimplemented!();
    }
}
