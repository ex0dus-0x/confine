//! policy.rs
//!
//!     Defines common confine policy format. Is used to then generate
//!     output configs for enforcers, or actual contained enforcement.

use std::io;
use std::io::Read;
use std::fs::File;
use std::boxed::Box;
use std::error::Error;
use std::path::PathBuf;
use std::collections::HashMap;

use serde::Deserialize;

use crate::syscall::SyscallAction;
use crate::enforcers::Enforcer;


// a type alias for a hashmap that provides a one-to-one mapping between syscall IDs and
// action to perform.
type PolicyMap = HashMap<u64, SyscallAction>;


/// Deserializable structure for actually storing parsed policy contents after
/// consuming TOML configuration. Comprises of several components in order to
/// dictate a "complete" configuration:
///
/// - one header manifest section
/// - one or multiple rule sections
#[derive(Deserialize, Debug, Clone)]
struct Policy {
    manifest: Manifest,
    rules: Option<Vec<Rule>>
}

/// a `Manifest` is a required header per confine config. It is used
/// to hold identifying information regarding the trace to be carried out,
/// both basic configs and for rule enforcement.
#[derive(Deserialize, Debug, Clone)]
struct Manifest {

    // name of task, job, identifier, etc.
    #[serde(alias = "name")]
    job_name: String,

    // represents entirety of command (plus args) to trace
    #[serde(alias = "command")]
    cmd_args: Vec<String>,

    // optionally represents an enforcer we want to generate
    enforcer: Option<String>,

    // TODO: output format
}


/// a `Rule` is a eserializable wrapper around a syscall rule
/// that eventually decomposes down to our policy map.
#[derive(Deserialize, Debug, Clone)]
struct Rule {
    // TODO: should also represent a group, or something else
    syscall: String,
    rule: SyscallAction
}


impl Policy {

    /// `from_file()` initializes a deserialized Policy struct
    /// from a configuration file
    fn from_file(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut contents = String::new();
        let mut file = File::open(&path)?;
        file.read_to_string(&mut contents)?;
        toml::from_str(&contents).map_err(|e| e.into())
    }

}


/// defines an interface to policy parsing and handling. Stores internal map of
/// policy actions to enforce, and an actual parsed policy
#[derive(Debug, Clone)]
pub struct PolicyInterface {
    policy: Option<Policy>,
    policy_map: PolicyMap,
    //enforcer: Box<Enforcer>,
}


impl PolicyInterface {

    /// `new_policy()` initializes an interface with a consumed policy file by parsing TOML into
    /// a deserializable Policy for enforcer interaction.
    pub fn new_policy(path: PathBuf) -> io::Result<Self> {
        let policy = Policy::from_file(path).unwrap();
        let policy_map = Self::gen_policy_map();

        Ok(Self {
                policy: Some(policy),
                policy_map: policy_map
        })
    }

    fn gen_policy_map() -> PolicyMap {
        unimplemented!();
    }
}
