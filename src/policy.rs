//! policy.rs
//!
//!     Defines common confine policy format. Is used to then generate
//!     output configs for enforcers, or actual contained enforcement.

use std::io;
use std::fs::File;
use std::boxed::Box;
use std::path::PathBuf;
use std::collections::HashMap;

use crate::syscall::SyscallAction;
use crate::enforcers::Enforcer;


// a type alias for a hashmap that provides a one-to-one mapping between syscall IDs and
// action to perform.
type PolicyMap = HashMap<u64, SyscallAction>;


/// Deserializable structure for actually storing parsed policy contents after consuming
/// TOML configuration.
#[derive(Deserialize)]
struct Policy {
    job_name: String,
    cmd_args: Option<Vec<String>>,
    enforcer: Option<String>
    // TODO
}

impl Policy {
    fn from_file(path: PathBuf) -> Self {
        let mut contents = String::new();
        let mut file = File::open(&path)?;
        file.read_to_string(&mut contents)?;
        toml::from_str(&contents)
    }

}


/// defines an interface to policy parsing and handling. Stores internal map of
/// policy actions to enforce, and an actual parsed policy
#[derive(Debug, Clone)]
pub struct PolicyInterface {
    policy: Option<Policy>
    policy_map: PolicyMap
    //enforcer: Box<Enforcer>,
}


impl PolicyInterface {

    /// `new_policy()` initializes an interface with a consumed policy file by parsing TOML into
    /// a deserializable Policy for enforcer interaction.
    pub fn new_policy(path: PathBuf) -> io::Result<Self> {
        let policy = Policy::from_file(path)?;

        let policy_map = Self::gen_policy_map
        Ok(Self { policy, policy_map })
    }
}
