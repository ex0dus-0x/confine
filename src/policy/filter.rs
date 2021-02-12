use serde::Deserialize;

use std::fs;
use std::path::PathBuf;

use crate::error::ConfineResult;
use crate::syscall::ParsedSyscall;

/// Declares an action parsed and applied to system calls before running.
#[derive(Debug, Clone)]
pub enum Action {
    Permit, // enable execution of system call
    Warn,   // warns user through STDOUT, but continue trace
    Block,  // SIGINT to trace execution when encountering call
    Log,    // log syscall execution to log
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = Deserialize::deserialize(deserializer)?;
        let action: Self = match raw.as_str() {
            "Warn" | "WARN" => Action::Warn,
            "Block" | "BLOCK" => Action::Block,
            "Log" | "LOG" => Action::Log,
            _ => Action::Permit,
        };
        Ok(action)
    }
}

/// Wrapper around a syscall rule that gets added to our policy map.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub syscall: String,
    pub action: Action,
}

/// Represents a parsed policy configuration used for enforcing against the trace.
#[derive(Deserialize, Debug, Clone)]
pub struct Filter {
    // if set, defines a path where syscalls are logged to
    pub logpath: Option<PathBuf>,

    // all rules that are to be enforced during dynamic tracing
    pub rules: Vec<Rule>,
}

impl Filter {
    /// Checks if a given syscall name is set as a rule, and return action to enforce if found.
    pub fn get_enforcement(&self, syscall: &str) -> Option<Action> {
        self.rules
            .iter()
            .find(|rule| rule.syscall == syscall)
            .map(|rule| rule.action.clone())
    }

    /// Enforces a LOG rule by writing to the specified input file the full system call that is
    /// marked to be logged.
    pub fn to_log(&self, syscall: ParsedSyscall) -> ConfineResult<()> {
        if let Some(path) = &self.logpath {
            fs::write(path, syscall.to_string()?)?;
        }
        Ok(())
    }
}
