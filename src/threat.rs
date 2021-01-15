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

    // strings that are read and written to
    strings: Vec<String>,

    // stores network addresses that are encountered
    networking: Vec<String>,

    // maps file I/O interactions
    file_io: HashMap<String, String>,

    // external commands executed
    commands: Vec<String>,
}

impl ThreatReport {

    /// Given a list of system calls, populate interface with only the syscall names.
    pub fn populate(&mut self, syscalls: &Vec<ParsedSyscall>) -> ConfineResult<()> {
        self.calls = syscalls.iter()
            .map(|syscall| syscall.name.clone())
            .collect();
        Ok(())
    }

    /// Given a parsed system call, match against syscalls to see if there is anything that we need
    /// to parse out for our final report
    pub fn check(&mut self, syscall: &ParsedSyscall) -> ConfineResult<()> {
        match syscall.name.as_str() {

            // get strings read/written to by file I/O
            "read" | "write" => {
                let buf_key: String = "char *buf".to_string();
                let buffer: &str = syscall.args.get(&buf_key).unwrap().as_str().unwrap();
                self.strings.push(buffer.to_string());
            },

            // if an open* syscall is encountered, get filename and mode
            "open" | "openat" => {
                // get filename
                let pathname_key: String = "const char *filename".to_string();
                let file: &str = syscall.args.get(&pathname_key).unwrap().as_str().unwrap();

                // get I/O flag
                let flag_key: String = "int flags".to_string();
                let flag: u64 = syscall.args.get(&flag_key).unwrap().as_u64().unwrap();

                // TODO: parse flag

                // insert path and its flag
                self.file_io.insert(file.to_string(), format!("{}", flag));
            },

            // if a child command is launched, record executable and arguments
            "execve" => {
                // get executable name
                let pathname_key: String = "const char *filename".to_string();
                let cmd: &str = syscall.args.get(&pathname_key).unwrap().as_str().unwrap();

                // get arguments to executable
                let args_key: String = "const char *const *argv".to_string();
                let args: &str = syscall.args.get(&args_key).unwrap().as_str().unwrap(); 
                self.commands.push(format!("{} {}", cmd, args));
            },
            _ => {}
        }
        Ok(())
    }
}
