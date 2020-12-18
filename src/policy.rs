//! Defines common confine policy format for enforcement.

use std::boxed::Box;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;

use crate::syscall::{Syscall, SyscallAction, SyscallGroup, SyscallManager};

// a type alias for a hashmap that provides a one-to-one mapping between syscall IDs and
// action to perform.
type PolicyMap = HashMap<u64, SyscallAction>;

/// Implements the variants a user input for a syscall rule can be.
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallType {
    Syscall(Syscall),
    Group(SyscallGroup),
    // .. TODO: other ways to identify syscalls
}

/// Deserializable wrapper around a syscall rule that gets added to our policy map.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: Option<String>,
    pub syscall: SyscallType,
    pub action: SyscallAction,
}

/// Parsed policy contents after consuming YAML configuration.
#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    pub rules: Option<Vec<Rule>>,
}

impl Policy {
    /// `from_file()` initializes a deserialized Policy struct from a configuration file.
    fn from_file(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut contents = String::new();
        let mut file = File::open(&path)?;
        file.read_to_string(&mut contents)?;
        serde_yaml::from_str(&contents).map_err(|e| e.into())
    }
}

/// Defines an interface to policy parsing and handling. Stores internal map of
/// policy actions to enforce, and an actual parsed policy
#[derive(Clone)]
pub struct PolicyInterface(PolicyMap);

impl PolicyInterface {
    /// Creates new policy map from given path.
    pub fn new_policy(path: PathBuf) -> io::Result<Self> {
        let policy = Policy::from_file(path).unwrap();
        Ok(Self(Self::gen_policy_map(policy)))
    }

    /// `gen_policy_map` is a helper that takes a parsed `Policy` and creates a
    /// HashMap mapping id values to enforced rules
    fn gen_policy_map(policy: Policy) -> PolicyMap {
        let mut map: PolicyMap = PolicyMap::new();

        // initialize a temporary syscall table for conversion reference
        // TODO: refactor to make this unnecessary
        let table = SyscallManager::parse_syscall_table().unwrap();

        if policy.rules.is_none() {
            return map;
        } else if let Some(_rules) = policy.rules {
            let _ = _rules.iter().map(|rule| {
                match &rule.syscall {
                    SyscallType::Syscall(s) => {
                        map.insert(
                            {
                                if let Some(e) = table.iter().find(|(_, v)| v == &&s.name) {
                                    *e.0
                                } else {
                                    panic!("Cannot find syscall");
                                }
                            },
                            rule.action.clone(),
                        );
                    }
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
