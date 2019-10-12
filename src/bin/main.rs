//! confine.rs
//!
//!     CLI interface for confine library modules. Implements tracing under two
//!     different modes, and provides deserialization support to serializable formats.

#[cfg(all(target_os = "linux",
          any(target_arch = "x86",
              target_arch = "x86_64")),
)]

extern crate clap;
extern crate confine;

#[macro_use] extern crate log;

use std::boxed::Box;
use std::path::PathBuf;
use std::process::Command;

use clap::{App, Arg};
use log::LevelFilter;

use confine::syscall::SyscallManager;
use confine::logger::TraceLogger;
use confine::trace::{ProcessHandler, Ptrace, Ebpf};


static LOGGER: TraceLogger = TraceLogger;


/// `TraceProc` provides a builder interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
struct TraceProc<'a> {
    mode: &'a (ProcessHandler + 'a),
    cmd: Command,
    json: bool

    // TODO: policy stuff
    //common_policy: Policy
    //output_policy: Enforcer
}

impl<'a> Default for TraceProc<'a> {
    fn default() -> Self {
        Self {
            mode: &Ptrace::new(),
            cmd: Command::new(""),
            json: false,

        }
    }
}


impl<'a> TraceProc<'a> {

    /// `new()` initializes a new TraceProc interface with PID and system call manager
    /// that stores parsed system calls.
    fn new(mode: &'a ProcessHandler) -> TraceProc<'a> {
        TraceProc { mode, ..TraceProc::default() }
    }

    /// `get_handler()` is a factory-like helper method that returns an instance of a trait object in a Box
    /// after parsing an argument string.
    #[inline]
    fn get_handler(handler_str: &str) -> Box<ProcessHandler + 'static> {
        match handler_str {
            "ptrace" => Box::new(Ptrace::new()),
            "ebpf" => Box::new(Ebpf::new()),
            _ => unreachable!()
        }
    }

    /// `trace_config()` builds up TraceProc with tracing configuration options.
    /// Once configured, tracing under the various modes of operation can be done.
    fn trace_config(&mut self, cmd: Command, json: bool) -> &TraceProc<'a> {
        self.cmd = cmd;
        self.json = json;
        self
    }

    /// `policy_config()` builds up TraceProc by parsing in a common confine policy and a specified
    /// output policy enforcer format (ie seccomp, apparmor)
    fn policy_config(&self, policy: PathBuf, /*enforcer: Enforcer*/) -> &TraceProc<'a> {
        self
    }

    /// `run_trace()` takes an initialized TraceProc with mode and executes a normal trace with
    /// the respective interface specified. Once complete and returns a generated trace manager, we
    /// output appropriately.
    fn run_trace(&self) -> () {
        //let out_manager: SyscallManager = self.mode.trace().unwrap();
    }

    /// `run_trace_policy()` does a normal `run_trace()`, but instead also enforces the set common
    /// security policy on top of the running tracee, with the purpose of enabling policy testing while
    /// in a trusted and secure environment.
    fn run_trace_policy(&self) -> () {
        //let out_manager: SyscallManager = self.mode.trace().unwrap();
    }

    /// `generate_policy()` takes a parsed confine policy and generates a enforcer policy from the specific
    /// enforcer module.
    fn generate_policy(&self, output: PathBuf) -> () {
        ()
    }
}


#[allow(unused_must_use)]
fn main() {
    let matches = App::new("confine")
        .about("security-focused process tracer with policy handling capabilities")
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

    // determine trace mode of operation
    let mode = matches.value_of("trace_mode").unwrap();

    info!("Utilizing trace mode: {}", mode);
    let _trace_mode = TraceProc::get_handler(mode);
    let trace_mode = Box::into_raw(_trace_mode);

    // initialize TraceProc interface
    info!("Starting up TraceProc instantiation");
    let mut proc = TraceProc::new(&trace_mode)
        .trace_config(cmd, matches.is_present("json"));
}
