//! Stores information parsed during a confine trace, parsing system calls and checking if any of
//! their behaviors may be suspicious, useful for determining various indicators of compromise when
//! investigating a running executable.
//!
//! Paper Reference: https://www.researchgate.net/publication/326638029_Understanding_Linux_Malware

use serde::Serialize;

use std::collections::HashMap;

mod capabilities;

use crate::error::ConfineResult;
use crate::syscall::ParsedSyscall;
use crate::threat::capabilities::ThreatCapabilities;

/// Defines a serializable threat report that is returned to the user by default if not specified
#[derive(Serialize, Default)]
pub struct ThreatReport {
    // stores only the system call names that are encountered
    syscalls: Vec<String>,

    // strings that are read and written to
    strings: Vec<String>,

    // stores network addresses that are encountered
    networking: Vec<String>,

    // maps file I/O interactions
    file_io: HashMap<String, String>,

    // external commands executed
    commands: Vec<String>,

    // sets capabilities that are observed within the running process
    capabilities: ThreatCapabilities,
}

impl ThreatReport {
    /// Given a list of system calls, populate interface with only the syscall names.
    pub fn populate(&mut self, syscalls: &[ParsedSyscall]) -> ConfineResult<()> {
        self.syscalls = syscalls
            .iter()
            .map(|syscall| syscall.name.clone())
            .collect();
        Ok(())
    }

    /// Given a parsed system call, match against syscalls to see if there is anything that we need
    /// to parse out for our final report
    pub fn check(&mut self, syscall: &ParsedSyscall) -> ConfineResult<()> {
        match syscall.name.as_str() {
            // get strings read/written to by file I/O, add to results, but also check for
            // potential persistence capability
            "read" | "write" => {
                let buf_key: String = "char *buf".to_string();
                let buffer: &str = syscall.args.get(&buf_key).unwrap().as_str().unwrap();

                // add string to vector
                if !buffer.is_empty() {
                    self.strings.push(buffer.to_string());
                }

                // check if a known for persistence
                self.capabilities.persistence.check(buffer.to_string());
            }

            // if an file IO syscall is encountered, get filename and mode
            "open" | "openat" | "stat" | "lstat" | "chdir" | "chmod" | "chown" | "lchown"
            | "fchownat" | "newfstatat" | "fchmodat" | "faccessat" | "mkdnod" | "mknodat" => {
                // get filename
                let pathname_key: String = "const char *filename".to_string();
                let file: &str = syscall.args.get(&pathname_key).unwrap().as_str().unwrap();

                // get I/O flag
                let flag_key: String = "int flags".to_string();
                let flag: u64 = match syscall.args.get(&flag_key) {
                    Some(val) => val.as_u64().unwrap(),
                    None => 0,
                };

                // TODO: parse flag

                // insert path and its flag
                self.file_io.insert(file.to_string(), format!("{}", flag));
            }

            // TODO: fstat

            // if a child command is launched, record executable and arguments
            "execve" | "execveat" | "execlp" | "execvp" => {
                // get executable name
                let pathname_key: String = "const char *filename".to_string();
                let cmd: &str = syscall.args.get(&pathname_key).unwrap().as_str().unwrap();

                // get arguments to executable
                let args_key: String = "const char *const *argv".to_string();
                let args: &str = syscall.args.get(&args_key).unwrap().as_str().unwrap();
                self.commands.push(format!("{} {}", cmd, args));
            }

            // check if syscalls for blocking are called
            "nanosleep" | "clock_nanosleep" => {
                self.capabilities.evasion.stalling = true;
            }

            // check for antidebug and potential process injection
            "ptrace" => {
                let req_key: String = "long request".to_string();
                let request: i64 = syscall.args.get(&req_key).unwrap().as_i64().unwrap();

                match request {
                    // PTRACE_TRACEME
                    0 => {
                        self.capabilities.evasion.antidebug = true;
                    }

                    // PTRACE_PEEK*
                    1 | 2 => {
                        self.capabilities.evasion.process_infect = true;
                    }

                    _ => {}
                }
            }

            // detect process deception by renaming
            "prctl" => {
                let option_key: String = "int option".to_string();
                let option: i64 = syscall.args.get(&option_key).unwrap().as_i64().unwrap();
                if option == 15 {
                    self.capabilities.evasion.deception = true;
                }
            }

            // detect fileless execution with memfd_create
            "memfd_create" => {
                self.capabilities.evasion.fileless_exec = true;
            }

            // TODO: networking
            _ => {}
        }
        Ok(())
    }
}
