//! Defines how system call representations are parsed from a given mapping configuration, and how
//! a `SyscallManager` is instantiated to consume system call input from the confine tracer.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::collections::HashMap;
use std::fmt::{self, Display};

mod defs;

use crate::syscall::defs::SYSCALL_TABLE;
use crate::error::{ConfineError, ConfineResult};

/// Maps argument names against the genericized value that is parsed
pub type ArgMap = HashMap<String, Value>;

/// Represents a parsed system call from a tracer, storing only the name, and collapsing arguments
/// as a hashmap between types and parsed values from registers in the calling convention.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSyscall {
    pub name: String,
    pub args: ArgMap,
}

impl ParsedSyscall {
    pub fn new(name: String, args: HashMap<String, Value>) -> Self {
        Self { name, args }
    }

    pub fn to_string(&self) -> ConfineResult<String> {
        let json: String = serde_json::to_string_pretty(self)?;
        Ok(json)
    }
}

impl Display for ParsedSyscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut syscall: String = format!("{}(", self.name);
        for (typename, name) in self.args.iter() {
            syscall.push_str(&format!("{} = {}, ", typename, name));
        }
        syscall.push_str("\x08\x08)");
        write!(f, "{}", syscall)
    }
}

/// Defines an interface for parsing and displaying system calls parsed by confine
#[derive(Serialize, Deserialize, Clone)]
pub struct SyscallManager(pub Vec<ParsedSyscall>);

impl SyscallManager {
    /// Generates syscall table to parse incoming system calls with
    pub fn new() -> ConfineResult<Self> {
        Ok(Self(Vec::new()))
    }

    /// Given a parsed syscall number from ORIG_RAX, get arguments for the specific system call
    /// such that tracer can appropriately read from memory addresses.
    pub fn get_arguments(&mut self, number: u64) -> ConfineResult<Vec<String>> {
        match SYSCALL_TABLE
            .iter()
            .position(|syscall| syscall.number == number)
        {
            Some(idx) => Ok(SYSCALL_TABLE[idx].args.clone()),
            None => Err(ConfineError::SyscallError(
                "Cannot find system call in map.".to_string(),
            )),
        }
    }

    /// Given a system call number, parse out the name that it corresponds to from the table.
    pub fn get_syscall_name(&mut self, number: u64) -> Option<&str> {
        SYSCALL_TABLE
            .iter()
            .find(|syscall| syscall.number == number)
            .map(|syscall| syscall.name)
    }

    /// Given a syscall number and parsed arguments, instantiate a `ParsedSyscall`, add to the
    /// final trace, and return a copy.
    pub fn add_syscall(&mut self, num: u64, args: ArgMap) -> ConfineResult<ParsedSyscall> {
        // get name from number with helper, exit if cannot be found
        let name: &str = match self.get_syscall_name(num) {
            Some(name) => name,
            None => {
                return Err(ConfineError::SyscallError(
                    "Cannot find syscall name from given number".to_string(),
                ));
            }
        };

        // instantiate new ParsedSyscall, and a deep copy to return
        let parsed: ParsedSyscall = ParsedSyscall::new(name.to_string(), args);
        let parsed_copy: ParsedSyscall = parsed.clone();

        // add original copy to final trace, and return deep copy
        self.0.push(parsed);
        Ok(parsed_copy)
    }
}
