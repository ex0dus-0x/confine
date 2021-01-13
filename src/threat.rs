//! Stores information parsed during a confine trace, parsing system calls and checking if any of
//! their behaviors may be suspicious, useful for determining various indicators of compromise when
//! investigating a running executable.

use serde::Serialize;

use std::collections::HashMap;

use crate::error::ConfineResult;
use crate::syscall::ParsedSyscall;

/// Defines a serializable threat report that is returned to the user by default if not specified
#[derive(Serialize, Default)]
pub struct ThreatReport {
    // stores only the system call names that are encountered
    calls: Vec<String>,

    // stores network addresses that are encountered
    networking: Vec<String>,

    // maps file I/O interactions
    file_io: HashMap<String, String>,

    // external commands executed
    commands: Vec<String>,
}

impl ThreatReport {

    /// Given a parsed system call, match against syscalls to see if there is anything that we need
    /// to parse out for our final report
    pub fn check(&self, syscall: &ParsedSyscall) -> ConfineResult<()> {
        match syscall.name.as_str() {
            "execve" => {},
            _ => {}
        }
        todo!()
    }
}
