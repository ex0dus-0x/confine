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

use crate::enforcers::EnforcerType;
use crate::syscall::{
    Syscall, SyscallAction,
    SyscallGroup, SyscallManager
};


// a type alias for a hashmap that provides a one-to-one mapping between syscall IDs and
// action to perform.
type PolicyMap = HashMap<u64, SyscallAction>;


/// a `Manifest` is a required header per confine config. It is used
/// to hold identifying information regarding the trace to be carried out,
/// both basic configs and for rule enforcement.
/// TODO: define more advanced configuration
#[derive(Deserialize, Debug, Clone)]
struct Manifest {

    // represents the stringified enforcer to generate policy for
    enforcer: Option<String>
}


/// `SyscallType` implements the variants a user input for a syscall rule
/// can be. It implements type conversion traits in order for serialization to
/// convert to a valid type (TODO)
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallType {
    Syscall(Syscall),
    Group(SyscallGroup),
    // .. TODO: other ways to identify syscalls
}


/// a `Rule` is a eserializable wrapper around a syscall rule
/// that eventually decomposes down to our policy map.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: Option<String>,
    pub syscall: SyscallType,
    pub action: SyscallAction
}


/// Deserializable structure for actually storing parsed policy contents after
/// consuming YAML configuration. Comprises of several components in order to
/// dictate a "complete" configuration:
///
/// - one header manifest section
/// - one or multiple rule sections
#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    manifest: Manifest,
    pub rules: Option<Vec<Rule>>
}


impl Policy {

    /// `from_file()` initializes a deserialized Policy struct from a configuration file.
    fn from_file(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut contents = String::new();
        let mut file = File::open(&path)?;
        file.read_to_string(&mut contents)?;
        serde_yaml::from_str(&contents).map_err(|e| e.into())
    }


    /// `get_enforcer()` returns an EnforcerType from a string serialized from the configuration
    /// manifest. If none is provided or isn't recognized, no enforcer will be used to generate a profile.
    pub fn get_enforcer(&self) -> EnforcerType {
        match &self.manifest.enforcer {
            Some(name) => {
                match name.as_str() {
                    "seccomp"   => EnforcerType::Seccomp,
                    "apparmor"  => EnforcerType::AppArmor,
                    _           => EnforcerType::Default
                }
            }
            None => EnforcerType::Default
        }
    }

}


/// defines an interface to policy parsing and handling. Stores internal map of
/// policy actions to enforce, and an actual parsed policy
#[derive(Debug, Clone)]
pub struct PolicyInterface {
    enforcer: EnforcerType,
    policy_map: PolicyMap
}


impl PolicyInterface {

    /// `new_policy()` initializes an interface with a consumed policy file by parsing YAML into
    /// a deserializable Policy for enforcer interaction.
    pub fn new_policy(path: PathBuf) -> io::Result<Self> {
        let policy = Policy::from_file(path).unwrap();
        Ok(Self {
            enforcer: policy.get_enforcer(),
            policy_map: Self::gen_policy_map(policy)
        })
    }


    /// `gen_policy_map` is a helper that takes a parsed `Policy` and creates a
    /// HashMap mapping id values to enforced rules
    fn gen_policy_map(policy: Policy) -> PolicyMap {
        let mut map: PolicyMap = PolicyMap::new();

        // initialize a temporary syscall table for conversion reference
        // TODO: refactor to make this unnecessary
        let table = SyscallManager::parse_syscall_table().unwrap();

        if let None = policy.rules {
            return map;
        }

        else if let Some(_rules) = policy.rules {
            let _ = _rules.iter().map(|rule| {
                match &rule.syscall {
                    SyscallType::Syscall(s) => {
                        map.insert({
                            if let Some(e) = table.iter().find(|(_,v)| { v == &&s.name }) {
                                *e.0
                            } else {
                                panic!("Cannot find syscall");
                            }
                        }, rule.action.clone());
                    },
                    SyscallType::Group(_g) => {
                        //map.insert(g, rule.action);
                        unimplemented!();
                    }
                }
            });
        }
        map
    }
}
