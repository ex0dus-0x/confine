//! Stores information parsed during a confine trace, parsing system calls and checking if any of
//! their behaviors may be suspicious, useful for determining various indicators of compromise when
//! investigating a running executable.
//!
//! Paper Reference: https://www.researchgate.net/publication/326638029_Understanding_Linux_Malware

use serde::Serialize;

use std::collections::HashMap;

use crate::error::ConfineResult;
use crate::syscall::ParsedSyscall;

/// Represents capabilities that are detected during execution and monitoring syscall behaviors.
#[derive(Serialize, Default)]
pub struct ThreatCapabilities {
    ///////////////////////
    // EVASION TECHNIQUES
    ///////////////////////
    pub stalling: bool,

    // checks if `ptrace` is used to determine if debugging is done
    pub antidebug: bool,

    // checks if `ptrace` is attempting inject or intrude on other processes
    pub process_infect: bool,

    ///////////////////////
    // PERSISTENCE TECHNIQUES
    ///////////////////////

    // set if startup service paths are interacted with
    pub init_persistence: bool,

    // set if time-based crontab paths are interacted with
    pub time_persistence: bool,

    // set if sample does any type of file process renaming with prctl + PR_SET_NAME
    pub process_renaming: bool,
}

impl ThreatCapabilities {
    /// Given a parsed pathstring, determine if it is a commonly used path for some type of
    /// persistence strategy.
    pub fn check_persistence(&mut self, path: String) {
        // check if services are created in any known paths
        let init_persistence: Vec<&str> = vec![
            "/etc/rc.d/rc.local",
            "/etc/rc.conf",
            "/etc/init.d/",
            "/etc/rcX.d/",
            "/etc/rc.local",
            ".bashrc",
            ".bash_profile",
        ];
        if init_persistence.iter().any(|&p| path.contains(p)) {
            self.init_persistence = true;
        }

        // check if time-based jobs are created in known paths
        let time_persistence: Vec<&str> =
            vec!["/etc/cron.hourly/", "/etc/crontab", "/etc/cron.daily/"];
        if time_persistence.iter().any(|&t| path.contains(t)) {
            self.time_persistence = true;
        }
    }
}

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
                self.capabilities.check_persistence(buffer.to_string());
            }

            // if an file IO syscall is encountered, get filename and mode
            "open" | "openat" | "stat" | "fstat" | "lstat" | "chdir" | "chmod" | "chown"
            | "lchown" | "fchownat" | "newfstatat" | "fchmodat" | "faccessat" | "mkdnod"
            | "mknodat" => {
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
                self.capabilities.stalling = true;
            }

            // check for antidebug and potential process injection
            "ptrace" => {
                let req_key: String = "long request".to_string();
                let request: i64 = syscall.args.get(&req_key).unwrap().as_i64().unwrap();

                match request {
                    // PTRACE_TRACEME
                    0 => {
                        self.capabilities.antidebug = true;
                    }

                    // PTRACE_PEEK*
                    1 | 2 => {
                        self.capabilities.process_infect = true;
                    }

                    _ => {}
                }
            }

            // detect process renaming technique
            "prctl" => {
                let option_key: String = "int option".to_string();
                let option: i64 = syscall.args.get(&option_key).unwrap().as_i64().unwrap();
                if option == 15 {
                    self.capabilities.process_renaming = true;
                }
            }

            // TODO: networking
            _ => {}
        }
        Ok(())
    }
}
