//! syscall.rs
//!
//!     Defines struct interface for system calls.
//!
//!     Implements a parser for unistd.h's syscall table
//!     in order to generate system calls with correct names.

use std::io;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;

use regex::Regex;
use serde::Serialize;
use serde_json::Result;

// path to unistd file with syscall number definitions
static SYSCALL_TABLE: &str = "/usr/include/asm/unistd_64.h";

// regex for parsing macro definitions of syscall numbers
static SYSCALL_REGEX: &str = r"#define\s*__NR_(\w+)\s*(\d+)";

// type alias for syscall table hashmap
type SyscallTable = HashMap<u64, String>;


/// Defines an arbitrary syscall, with support for de/serialization
/// with serde_json.
#[derive(Serialize)]
pub struct Syscall {
    number: u64,
    name: String,
    args: Vec<u64>,
}


/// SyscallManager stores a vector of Syscalls and manages a HashMap
/// that stores syscall num and name mappings.
#[derive(Serialize)]
#[serde(rename = "syscalls")]
pub struct SyscallManager {
    syscalls: Vec<Syscall>,

    #[serde(skip)]
    pub _syscall_table: SyscallTable
}


impl Default for SyscallManager {
    fn default() -> Self {
        let syscall_table = SyscallManager::_parse_syscall_table()
            .expect("cannot parse syscall table.");

        Self {
            syscalls: Vec::new(),
            _syscall_table: syscall_table
        }
    }
}

impl SyscallManager {

    pub fn new() -> Self {
        Self::default()
    }

    /// `_parse_syscall_table()` is a helper method that parses a "syscall table"
    /// and instantiates a HashMap that stores the syscall num as a key and the name
    /// as the value.
    #[inline]
    fn _parse_syscall_table() -> io::Result<SyscallTable> {

        // read unistd.h for macro definitions
        let mut tbl_file = File::open(SYSCALL_TABLE)?;
        let mut contents = String::new();
        tbl_file.read_to_string(&mut contents)?;

        lazy_static! {
            static ref RE: Regex = Regex::new(SYSCALL_REGEX).expect("cannot initialize regex object");
        }

        // find matches and store as 2-ary tuple in vector
        let matches: Vec<(u64, String)> = RE.captures_iter(&contents.as_str()).filter_map(|cap| {
            let groups = (cap.get(2), cap.get(1));
            match groups {
                (Some(ref num), Some(ref name)) => {
                    Some((num.as_str().parse::<u64>().expect("unable to parse u64 syscall number"),
                    name.as_str().to_string()))
                },
                _ => None
            }
        }).collect();

        let syscall_table: HashMap<_, _> = matches.into_iter().collect();
        Ok(syscall_table)
    }


    /// `add_syscall()` finds a corresponding syscall name from
    /// a parsed syscall table and instantiates and stores a new Syscall.
    pub fn add_syscall(&mut self, syscall_num: u64, args: Vec<u64>) -> () {

        // retrieve syscall name from HashMap by syscall_num key
        let syscall_name = match self._syscall_table.get(&syscall_num) {
            Some(s) => s,
            None => {
                panic!("unable to determine corresponding syscall for number {}", syscall_num);
            }
        };

        // initialize Syscall definition and store
        let syscall = Syscall {
            number: syscall_num,
            name: syscall_name.to_string(),
            args: args
        };
        self.syscalls.push(syscall);
    }


    pub fn to_json(&mut self) -> Result<String> {
        serde_json::to_string(&self)
    }
}


impl fmt::Display for SyscallManager {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        // collect syscalls into formattable string
        let syscalls: Vec<String> = self.syscalls
            .iter()
            .map(|x| format!("{}({:?})", x.name, x.args))
            .collect();
        write!(f, "{:?}", syscalls)
    }
}
