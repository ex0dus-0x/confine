//! Defines common confine policy format for enforcement. Consumes a configuration which is then
//! used by confine when tracing to handle call behavior, acting as a dynamic firewall.
use std::boxed::Box;
use std::error::Error;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::syscall::{ParsedSyscall, SyscallAction};

/*
/// Implements the variants a user input for a syscall rule can be.
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallType {
    Syscall(Syscall),
    Group(SyscallGroup),

*/

/// Wrapper around a syscall rule that gets added to our policy map.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: Option<String>,
    pub syscall: String,
    pub action: SyscallAction,
}

// Represents a parsed policy configuration used for enforcing against the trace.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
    pub logpath: Option<PathBuf>,
    pub rules: Option<Vec<Rule>>,
}

impl Policy {
    /// Instantiates a strongly typed `Policy` from a given
    pub fn new(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let contents: String = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&contents).map_err(|e| e.into())
    }

    /// Enforces a LOG rule by writing to the specified input file the full system call that is
    /// marked to be logged.
    pub fn to_log(&self, _syscall: ParsedSyscall) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
