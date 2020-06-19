//! Defines struct interface for system calls. Implements a parser for `unistd.h`'s syscall
//! table in order to generate system calls with correct names.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use regex::Regex;
use serde::{Deserialize, Serialize};

// TODO: check paths preemptively

// path to unistd file with syscall number definitions, based on arch
#[cfg(target_arch = "x86_64")]
//static SYSCALL_TABLE: &str = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h";
static SYSCALL_TABLE: &str = "/usr/include/asm/unistd_64.h";

#[cfg(target_arch = "x86")]
//static SYSCALL_TABLE: &str = "/usr/include/i386-linux-gnu/asm/unistd_32.h";
static SYSCALL_TABLE: &str = "/usr/include/asm/unistd_32.h";

// regex for parsing macro definitions of syscall numbers
static SYSCALL_REGEX: &str = r"#define\s*__NR_(\w+)\s*(\d+)";

// type alias for syscall table hashmap
pub type SyscallTable = HashMap<u64, String>;

/// declares an action parsed by the userspace application and applied to
/// system calls before trace.
#[derive(Deserialize, Debug, Clone)]
pub enum SyscallAction {
    Permit,       // enable execution of system call
    Warn,         // warns user through STDOUT, but continue trace
    Block,        // SIGINT to trace execution when encountering call
    Log(PathBuf), // log syscall execution to log
}

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

/// Enables us to readily convert a syscall name to a group, useful during
/// execution and rule enforcement.
impl From<&str> for SyscallGroup {
    fn from(input: &str) -> Self {
        unimplemented!()
    }
}

impl Default for SyscallGroup {
    fn default() -> Self {
        SyscallGroup::Ungrouped
    }
}

/// Defines an arbitrary syscall, with support for de/serialization
/// with serde_json.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Syscall {
    pub number: u64,
    pub name: String,
    args: Vec<u64>,

    #[serde(skip)]
    group: SyscallGroup,

    // Defines enforcement action when encountering system call.
    // TODO: silence in trace output if not allowed
    #[serde(skip)]
    status: Option<SyscallAction>,
}

/// `SyscallManager` stores a vector of Syscalls and manages a HashMap
/// that stores syscall num and name mappings.
#[derive(Serialize, Clone)]
#[serde(rename = "syscalls")]
pub struct SyscallManager {
    syscalls: Vec<Syscall>,

    #[serde(skip)]
    pub syscall_table: SyscallTable,
}

/// `SysManagerError` defines failures that can occur during
/// system call parsing.
#[derive(Debug, Fail)]
pub enum SyscallError {
    #[fail(display = "File i/o error with parsing syscalls")]
    IOError(std::io::Error),

    #[fail(display = "System call number {} not supported", id)]
    UnsupportedSyscall { id: u64 },

    #[fail(display = "Cannot parse out a system call table. Reason: {}", reason)]
    SyscallTableError { reason: &'static str },
}

impl SyscallManager {
    /// `new()` initializes a manager with a parsed system call table,
    /// ready for storing syscalls.
    pub fn new() -> Self {
        let syscall_table = SyscallManager::parse_syscall_table().unwrap();
        Self {
            syscalls: Vec::new(),
            syscall_table: syscall_table,
        }
    }

    /// `parse_syscall_table()` is a helper method that parses a "syscall table"
    /// and instantiates a HashMap that stores the syscall num as a key and the name
    /// as the value.
    #[inline]
    pub fn parse_syscall_table() -> Result<SyscallTable, SyscallError> {
        // read unistd.h for macro definitions
        let mut tbl_file = File::open(SYSCALL_TABLE).map_err(SyscallError::IOError)?;

        let mut contents = String::new();
        tbl_file
            .read_to_string(&mut contents)
            .map_err(SyscallError::IOError)?;

        // TODO: return SyscallError
        lazy_static! {
            static ref RE: Regex = Regex::new(SYSCALL_REGEX).expect("cannot parse regex");
        }

        // find matches and store as 2-ary tuple in vector
        let matches: Vec<(u64, String)> = RE
            .captures_iter(&contents.as_str())
            .filter_map(|cap| {
                let groups = (cap.get(2), cap.get(1));
                match groups {
                    (Some(ref num), Some(ref name)) => {
                        Some(
                            // TODO: return SyscallError
                            (
                                num.as_str()
                                    .parse::<u64>()
                                    .expect("cannot parse u64 syscall id"),
                                name.as_str().to_string(),
                            ),
                        )
                    }
                    _ => None,
                }
            })
            .collect();

        let syscall_table: HashMap<_, _> = matches.into_iter().collect();
        Ok(syscall_table)
    }

    /// `add_syscall()` finds a corresponding syscall name from
    /// a parsed syscall table and instantiates and stores a new Syscall.
    pub fn add_syscall(&mut self, syscall_num: u64, args: Vec<u64>) -> Result<(), SyscallError> {
        // retrieve syscall name from HashMap by syscall_num key
        let syscall_name = match self.syscall_table.get(&syscall_num) {
            Some(s) => s,
            None => {
                return Err(SyscallError::UnsupportedSyscall { id: syscall_num });
            }
        };

        // initialize Syscall definition and store
        let syscall = Syscall {
            number: syscall_num,
            name: syscall_name.to_string(),
            args: args,
            group: SyscallGroup::default(),
            status: None,
        };
        self.syscalls.push(syscall);
        Ok(())
    }

    /// helper that returns our system calls in a prettified JSON format
    pub fn to_json(&mut self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self)
    }
}

impl fmt::Display for SyscallManager {
    /// collect system calls and output in readable format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let syscalls: Vec<String> = self
            .syscalls
            .iter()
            .map(|x| format!("{}({:?})", x.name, x.args))
            .collect();
        write!(f, "{:?}", syscalls)
    }
}
