//! Defines common confine policy format for enforcement. Consumes a configuration which is then
//! used by confine when tracing to handle call behavior, acting as a dynamic firewall.
use std::boxed::Box;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::syscall::ParsedSyscall;

/*
/// Implements the variants a user input for a syscall rule can be.
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallType {
    Syscall(Syscall),
    Group(SyscallGroup),

*/

/// Declares an action parsed by the userspace application and applied to
/// system calls before trace.
#[derive(Deserialize, Debug, Clone)]
pub enum Action {
    Permit, // enable execution of system call
    Warn,   // warns user through STDOUT, but continue trace
    Block,  // SIGINT to trace execution when encountering call
    Log,    // log syscall execution to log
}

/// Wrapper around a syscall rule that gets added to our policy map.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub syscall: String,
    pub action: Action,
}

// Represents a parsed policy configuration used for enforcing against the trace.
#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    pub logpath: Option<PathBuf>,
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Instantiates a strongly typed `Policy` from a given
    pub fn new(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let contents: String = fs::read_to_string(path)?;
        serde_yaml::from_str(&contents).map_err(|e| e.into())
    }

    /// Checks if a given syscall name is set as a rule, and return action to enforce if found.
    pub fn get_enforcement(&self, syscall: &String) -> Option<Action> {
        self.rules
            .iter()
            .find(|rule| rule.name == *syscall)
            .map(|rule| rule.action.clone())
    }

    /// Enforces a LOG rule by writing to the specified input file the full system call that is
    /// marked to be logged.
    pub fn to_log(&self, syscall: ParsedSyscall) -> Result<(), Box<dyn Error>> {
        if let Some(path) = &self.logpath {
            fs::write(path, syscall.to_string()?)?;
        } else {
            todo!();
        }
        Ok(())
    }
}
