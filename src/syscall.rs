//! Defines how system call representations are parsed from a given mapping configuration, and how
//! a `SyscallManager` is instantiated to consume system call input from the confine tracer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{ConfineError, ConfineResult};

/*
/// Defines enum for various system call group, which classifies syscalls to groups that
/// define generalized functionality.
/// Inspired by: http://seclab.cs.sunysb.edu/sekar/papers/syscallclassif.htm
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallGroup {
    FileIO,
    ProcessControl,
    NetworkAccess,
    MessageQueues,
    SharedMemory,
    TimeControl,
    Ungrouped, // .. other miscellaneous system-related tasks
}
*/

/// Maps argument names against the genericized value that is parsed
pub type ArgMap = HashMap<String, Value>;

/// Represents a single system call definition, including its syscall number, name,
/// and a vector of argument definitions.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u64,
    pub name: String,
    pub args: Vec<String>,
}

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

/// Defines an interface for parsing and displaying system calls parsed by confine
#[derive(Serialize, Deserialize, Clone)]
pub struct SyscallManager {
    /// stores the system calls that are parsed during confine execution
    syscalls: Vec<ParsedSyscall>,

    /// stores all current state of system calls for the kernel
    #[serde(skip)]
    pub syscall_table: Vec<Syscall>,
}

impl SyscallManager {
    /// Generates syscall table to parse incoming system calls with
    pub fn new() -> ConfineResult<Self> {
        let syscall_table = SyscallManager::parse_syscall_table().map_err(|_| {
            ConfineError::SyscallError("cannot parse system call table".to_string())
        })?;
        Ok(Self {
            syscalls: Vec::new(),
            syscall_table,
        })
    }

    /// Helper to parse JSON-based system call mapping to store for confine to consult when
    /// executing a trace.
    #[inline]
    pub fn parse_syscall_table() -> ConfineResult<Vec<Syscall>> {
        // get path to syscall JSON configuration to parse with crate root
        let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.push("extras/syscall_table.json");

        // read from JSON data from path
        let syscall_data: String = std::fs::read_to_string(root)?;

        // deserialize as Vec of strongly typed system calls and args
        let res: Vec<Syscall> = serde_json::from_str(&syscall_data)?;
        Ok(res)
    }

    /// Given a parsed syscall number from ORIG_RAX, get arguments for the specific system call
    /// such that tracer can appropriately read from memory addresses.
    pub fn get_arguments(&mut self, number: u64) -> ConfineResult<Vec<String>> {
        match self
            .syscall_table
            .iter()
            .position(|syscall| syscall.number == number)
        {
            Some(idx) => Ok(self.syscall_table[idx].args.clone()),
            None => Err(ConfineError::SyscallError(
                "Cannot find system call in map.".to_string(),
            )),
        }
    }

    /// Given a system call number, parse out the name that it corresponds to from the table.
    pub fn get_syscall_name(&mut self, number: u64) -> Option<String> {
        self.syscall_table
            .iter()
            .find(|syscall| syscall.number == number)
            .map(|syscall| syscall.name.clone())
    }


    /// Given a syscall number and parsed arguments, instantiate a `ParsedSyscall`, add to the
    /// final trace, and return a copy.
    pub fn add_syscall(&mut self, num: u64, args: ArgMap) -> ConfineResult<ParsedSyscall> {
        // get name from number with helper, exit if cannot be found
        let name: String = match self.get_syscall_name(num) {
            Some(name) => name,
            None => {
                return Err(ConfineError::SyscallError(
                    "Cannot find syscall name from given number".to_string(),
                ));
            }
        };

        // instantiate new ParsedSyscall, and a deep copy to return 
        let parsed: ParsedSyscall = ParsedSyscall::new(name, args);
        let parsed_copy: ParsedSyscall = parsed.clone();

        // add original copy to final trace, and return deep copy
        self.syscalls.push(parsed);
        Ok(parsed_copy)
    }
}
