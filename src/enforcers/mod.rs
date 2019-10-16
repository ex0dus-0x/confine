//! mod.rs
//!
//!     Implements trait method for enforcers to bound to in module.

use crate::policy::Policy;


pub trait Enforcer {

    /// `new()` initializes an enforcer with a specific policy for either outputting or enforcement
    /// under a contained runtime.
    fn new(policy: Policy) -> Self;

    /// `output_policy()` is used to generate a configuration for the specific enforcer module.
    fn output_policy(&self);

    /// `enforce_policy()` is a default trait method that is in charge of actually enforcing a parsed
    /// Policy during a trace execution under a contained environment
    fn enforce_policy(&self) -> () {
    }
}
