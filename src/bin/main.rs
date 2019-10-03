//! confine.rs
//!
//!     CLI interface for confine library modules. Implements tracing under two
//!     different modes, and provides deserialization support to serializable formats.

#[cfg(all(target_os = "linux",
          any(target_arch = "x86",
              target_arch = "x86_64")),
)]

extern crate clap;
extern crate regex;
extern crate libc;
extern crate nix;
extern crate bcc;
extern crate goblin;

extern crate serde;
extern crate serde_json;

#[macro_use] extern crate log;

extern crate confine;

use std::io;
use std::process::Command;
use std::ffi::CString;

use libc::{pid_t, c_int};

use nix::unistd;
use nix::sys::signal;

use clap::{App, Arg};
use log::LevelFilter;

use confine::logger::TraceLogger;
use confine::trace::ptrace::helpers;
use confine::trace::ptrace::consts::{options, regs};
use confine::syscall::SyscallManager;



static LOGGER: TraceLogger = TraceLogger;


/// `TraceMode` defines the two possible modes we can use in order to perform tracing: our fallback `ptrace` mode
/// for older and arch-independent systems, and our modus operandi `ebpf` for modern and fast systems.
enum TraceMode { Ptrace, Ebpf }


/// `TraceProc` provides a builder interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
struct TraceProc {
    cmd: Command,
    args: Vec<String>,

    pid: pid_t,
    manager: SyscallManager,

    json: bool,
    trace_mode: TraceMode,
    func_log: usize
}


impl Default for TraceProc {
    fn default() -> Self {
        Self {
            cmd: Command::new("ls"),
            args: Vec::new(),

            pid: 0,
            manager: SyscallManager::new(),

            json: false,
            trace_mode: TraceMode::Ebpf,
            func_log: 0
        }
    }
}


impl TraceProc {

    /// `new()` initializes a new TraceProc interface with PID and system call manager
    /// that stores parsed system calls.
    fn new(cmd: Command, args: Vec<String>) -> Self {
        Self { cmd, args, ..Self::default() }
    }


    /// `with_config()` allows us to build up a TraceProc with configuration options set
    /// by the user.
    fn with_config(&mut self, json: bool, trace_mode: TraceMode, func_log: usize) -> &Self {
        self.json = json;
        self.trace_mode = trace_mode;
        self.func_log = func_log;
        self
    }


    /// `get_proc` builds up TraceProc with initialized child process ID.
    fn get_proc(&mut self, pid: pid_t) -> &Self {
        self.pid = pid;
        self
    }


    fn trace(&mut self) -> io::Result<()> {
        // TODO
        Ok(())
    }


    /// `output()` is called after a run in order return trace results the configured format,
    /// either as raw unstructured trace or in JSON
    fn output(&mut self) -> () {

        // JSON
        if self.json {
            println!("{}", self.manager.to_json().expect("unable to output to JSON"));
        }

        // Default raw output
        else {
            println!("{}", self.manager);
        }
    }


    /// `step()` defines the main instrospection performed ontop of the traced process, using
    /// ptrace to parse out syscall registers for output.
    fn step(&mut self) -> io::Result<Option<c_int>> {

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_ENTER");
        helpers::syscall(self.pid)?;
        if let Some(status) = self.wait().unwrap() {
            return Ok(Some(status));
        }

        // determine syscall number and initialize
        let syscall_num = match self.get_syscall_num() {
            Ok(num) => num,
            Err(e) => panic!("Cannot retrieve syscall number. Reason {:?}", e),
        };
        debug!("Syscall number: {:?}", syscall_num);

        // retrieve first 3 arguments from syscall
        let mut args: Vec<u64> = Vec::new();
        for i in 0..2 {
            args.push(self.get_arg(i).unwrap());
        }

        // add syscall to manager
        self.manager.add_syscall(syscall_num, args);

        info!("ptrace-ing with PTRACE_SYSCALL to SYS_EXIT");
        helpers::syscall(self.pid)?;
        if let Some(status) = self.wait().unwrap() {
            return Ok(Some(status));
        }
        Ok(None)
    }


    /// `wait()` wrapper to waitpid/wait4, with error-checking in order
    /// to return proper type back to developer.
    fn wait(&self) -> io::Result<Option<c_int>> {
        let mut status = 0;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);

            // error-check status set
            if libc::WIFEXITED(status) {
                Ok(Some(libc::WEXITSTATUS(status)))
            } else {
                Ok(None)
            }
        }
    }


    /// `get_arg()` is called to introspect current process
    /// states register values in order to determine syscall
    /// and arguments passed.
    fn get_arg(&mut self, reg: u8) -> io::Result<u64> {

        #[cfg(target_arch = "x86_64")]
        let offset = match reg {
            0 => regs::RDI,
            1 => regs::RSI,
            2 => regs::RDX,
            3 => regs::RCX,
            4 => regs::R8,
            5 => regs::R9,
            _ => panic!("Unmatched argument offset")
        };

        /* TODO: implement registers
        #[cfg(target_arch = "x86")]
        let offset = match reg {
            0 => regs::EDI,
            1 => regs::ESI,
            2 => regs::EDX,
            3 => regs::ECX,
            4 => regs::E8,
            5 => regs::E9,
            _ => panic!("Unmatched argument offset")
        };
        */

        helpers::peek_user(self.pid, offset).map(|x| x as u64)
    }


    /// `get_syscall_num()` uses ptrace with PEEK_USER to return the
    /// syscall num from ORIG_RAX.
    fn get_syscall_num(&mut self) -> io::Result<u64> {
        helpers::peek_user(self.pid, regs::ORIG_RAX).map(|x| x as u64)
    }
}


#[inline]
fn ptrace_main(mut pid: TraceProc) -> io::Result<()> {

    // fork child process
    info!("Forking child process from parent");
    let result = unistd::fork().expect("unable to call fork(2)");
    match result {
        unistd::ForkResult::Parent { child } => {

            info!("Tracing parent process");
            pid.get_proc(child.as_raw());

            // in parent, wait for process event from child
            info!("Waiting for child process to send SIGSTOP");
            if let Err(e) = pid.wait() {
                panic!("Error: {:?}", e);
            }

            // set trace options
            info!("Setting trace options with PTRACE_SETOPTIONS");
            helpers::set_options(child.as_raw(), options::PTRACE_O_TRACESYSGOOD.into());

            // execute loop that examines through syscalls
            info!("Executing parent with tracing");
            loop {
                match pid.step() {
                    Err(e) => panic!("Unable to run tracer. Reason: {:?}", e),
                    Ok(Some(status)) => {
                        if status == 0 {
                            break;
                        } else {
                            debug!("Status reported: {:?}", status);
                        }
                    },
                    other => { other?; }
                }
            }
        },
        unistd::ForkResult::Child => {
            info!("Tracing child process");

            // start tracing process, notifying parent through wait(2)
            info!("Child process executing PTRACE_TRACEME");
            helpers::traceme();

            // send a SIGSTOP in order to stop child process for parent introspection
            info!("Sending SIGTRAP, going back to parent process");
            signal::kill(unistd::getpid(), signal::Signal::SIGSTOP);

            // execute child process with tracing until termination
            info!("Executing rest of child execution until termination");
            let c_cmd = CString::new(pid.args[0].clone()).expect("failed to initialize CString command");
            let c_args: Vec<CString> = pid.args.iter()
                .map(|arg| CString::new(arg.as_str()).expect("CString::new() failed"))
                .collect();
            unistd::execvp(&c_cmd, &c_args).ok().expect("failed to call execvp(2) in child process");
        }
    }
    Ok(())
}


#[inline]
fn ebpf_main(pid: TraceProc) -> io::Result<()> {
    Ok(())
}


#[allow(unused_must_use)]
fn main() {
    let matches = App::new("confine")
        .about("security-focused process tracer with capabilities")
        .author("Trail of Bits")
        .arg(
            Arg::with_name("command")
                .raw(true)
                .help("Command to analyze as child, including positional arguments.")
                .takes_value(true)
                .required(true)
        )

        // TODO: policy file - detection
        // TODO: policy file - generation

        .arg(
            Arg::with_name("trace_mode")
                .short("m")
                .long("trace_mode")
                .possible_values(&["ebpf", "ptrace"])
                .default_value("ebpf")
                .takes_value(true)
                .value_name("TRACE_MODE")
                .required(false)
        )
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Output system call trace as JSON.")
                .takes_value(false)
                .required(false)
        )
        .arg(
            Arg::with_name("func_log")
                .short("f")
                .long("func_log")
                .help("Level of trace function output (default is 0, syscall only).")
                .takes_value(true)
                .value_name("FUNC_LOG_LEVEL")
                .required(false)
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .long("verbosity")
                .help("Sets verbosity for program logging output.")
                .multiple(true)
                .takes_value(false)
                .required(false)
        ).get_matches();


    // initialize logger with basic logging levels
    let level_filter = match matches.occurrences_of("verbosity") {
        2       => LevelFilter::Debug,
        1       => LevelFilter::Info,
        0 | _   => LevelFilter::Off,
    };
    log::set_logger(&LOGGER).expect("unable to initialize logger");
    log::set_max_level(level_filter);
    info!("Initialized logger");

    // collect args into vec and convert to String for lifetime
    let _args: Vec<&str> = matches.values_of("command")
                          .unwrap()
                          .collect::<Vec<&str>>();
    let args: Vec<String> = _args.iter().map(|s| s.to_string()).collect();

    debug!("Command and arguments: {:?}", args);

    // initialize command
    let mut cmd = Command::new(args[0].clone());
    if args.len() > 1 {
        for arg in args.iter().skip(1) {
            debug!("Adding arg: {}", arg);
            cmd.arg(arg);
        }
    }

    // initialize TraceProc interface
    let mut pid = TraceProc::new(cmd, args);

    let trace_mode: TraceMode = match matches.value_of("trace_mode") {
        Some(e) => match e {
            "ebpf"      => TraceMode::Ebpf,
            "ptrace"    => TraceMode::Ptrace,
            _           => panic!("Unknown trace mode specified.")
        },
        None => TraceMode::Ebpf
    };

    let func_log: usize = match matches.value_of("func_log") {
        Some(e) => e.parse::<usize>().unwrap(),
        None    => 0 as usize,
    };

    // initialize configuration with options
    pid.with_config(
        matches.is_present("json"),
        trace_mode,
        func_log
    );

    // trace based on configuration
    pid.trace();
}
