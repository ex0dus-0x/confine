//! seccomp.rs
//!
//!

use std::enforcers::Enforcer;


//! `Seccomp` structure that encapsulates the
//!
pub struct Seccomp;


impl Enforcer for Seccomp {
    fn from_policy(policy: PolicyInterface) -> Self {


    }


    fn output_policy(&self) -> &'static str {


    }
}
