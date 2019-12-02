//! mod.rs
//!
//!     Implements trait method for enforcers to bound to in module.

use serde::Deserialize;

use crate::policy::PolicyInterface;


/// `EnforcerType` represents enforcers currently supported with confine policy generation, used for some
/// configuration matching after deserialization.
#[derive(Deserialize, Debug, Clone)]
pub enum EnforcerType {
    Seccomp,
    AppArmor,
    Unsupported(String)
}


/// the `Enforcer` trait provides a base interface for all structs that implement functionality for a
/// Linux security module that requires the enforcement of rules from some user-input profile. Each enforcer
/// implemented will consume a confine `Policy` and output its own specific profile for use with the specific
/// Linux module
pub trait Enforcer {

    /// `new()` initializes an enforcer with a specific policy for either outputting or enforcement
    /// under a contained runtime.
    fn new(policy: PolicyInterface) -> Self;

    /// `output_policy()` is used to generate a configuration for the specific enforcer module.
    fn output_policy(&self);

    /// `enforce_policy()` is a default trait method that is in charge of actually enforcing a parsed
    /// Policy during a trace execution under a contained environment
    fn enforce_policy(&self) {
        unimplemented!();
    }
}
