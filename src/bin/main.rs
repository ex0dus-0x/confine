//! confine.rs
//!
//!     CLI interface for confine library modules. Implements tracing under two
//!     different modes, and provides deserialization support to serializable formats.

#[cfg(all(target_os = "linux",
          any(target_arch = "x86",
              target_arch = "x86_64")),
)]

extern crate clap;
extern crate failure;
extern crate confine;

#[macro_use] extern crate log;

use std::boxed::Box;
use std::path::PathBuf;

use clap::{App, Arg};
use log::LevelFilter;
use failure::Error;

use confine::syscall::SyscallManager;
use confine::logger::TraceLogger;
use confine::policy::Policy;
use confine::trace::{ProcessHandler, Ptrace, Ebpf};


static LOGGER: TraceLogger = TraceLogger;


/// `TraceProc` provides a builder interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
struct TraceProc {
    mode: Box<ProcessHandler>,
    manager: Option<SyscallManager>,
    json: bool,
    common_policy: Option<Policy>,
}

impl Default for TraceProc {
    fn default() -> Self {
        Self {
            mode: Box::new(Ptrace::new()),
            manager: None,
            json: false,
            common_policy: None
        }
    }
}


impl TraceProc {

    /// `new()` initializes a new TraceProc interface with PID and system call manager
    /// that stores parsed system calls.
    fn new(mode: Box<ProcessHandler>) -> TraceProc {
        TraceProc { mode, ..TraceProc::default() }
    }

    /// `get_handler()` is a factory-like helper method that returns an instance of a trait object in a Box after
    /// parsing an argument string. We do this to be able to parse out a struct that implements the ProcessHandler
    /// trait bound.
    #[inline]
    fn get_handler(handler_str: &str) -> Box<ProcessHandler + 'static> {
        match handler_str {
            "ptrace" => Box::new(Ptrace::new()),
            "ebpf" => Box::new(Ebpf::new()),
            _ => unreachable!()
        }
    }

    /// `trace_config()` builds up TraceProc with tracing configuration options. Once configured, tracing under the
    /// various modes of operation can be done.
    fn trace_config(mut self, json: bool) -> TraceProc {
        self.json = json;
        self
    }

    /// `policy_config()` builds up TraceProc by parsing in a common confine policy and a specified
    /// output policy enforcer format (ie seccomp, apparmor)
    fn policy_config(self, policy: Option<PathBuf>, /*enforcer: Enforcer*/) -> TraceProc {
        self
    }

    /// `run_trace()` takes an initialized TraceProc with mode and execute a normal trace, and store to struct.
    /// Once traced, we can preemptively output the trace as well, in the case the user only wants a trace.
    fn run_trace(&mut self, args: Vec<String>, output: bool) -> Result<(), Error> {
        let table = Some(self.mode.trace(args)?);
        if output {
            if !self.json {
                println!("{}", table.unwrap())
            } else {
                println!("{}", table.unwrap().to_json()?);
            }
        }
        Ok(())
    }

    /// `run_trace_policy()` does a normal `run_trace()`, but instead also enforces the set common
    /// security policy on top of the running tracee, with the purpose of enabling policy testing while
    /// in a trusted and secure environment.
    fn run_trace_policy(&mut self, args: Vec<String>, output: bool) -> Result<(), Error> {
        self.run_trace(args, output)?;
        Ok(())
    }

    /// `generate_policy()` takes a parsed confine policy and generates a enforcer policy from the specific
    /// enforcer module, and returns a path for consumption.
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
                .help("Command to analyze as child, including positional arguments.")
                .raw(true)
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("policy_path")
                .help("Path to policy file to use for generation")
                .short("p")
                .long("policy")
                .takes_value(true)
                .value_name("POLICY_PATH")
                .required(false)
        )
        .arg(
            Arg::with_name("policy_enforcer")
                .help("Policy enforcer to use for generation")
                .short("e")
                .long("enforcer")
                .takes_value(true)
                .value_name("ENFORCER")
                .required(false)
        )
        .arg(
            Arg::with_name("trace_mode")
                .help("Mode used for process tracing (ebpf or ptrace).")
                .short("m")
                .long("trace_mode")
                .possible_values(&["ebpf", "ptrace"])
                .default_value("ptrace")
                .takes_value(true)
                .value_name("TRACE_MODE")
                .required(false)
        )
        .arg(
            Arg::with_name("json")
                .help("Output system call trace as JSON.")
                .short("j")
                .long("json")
                .takes_value(false)
                .required(false)
        )
       .arg(
            Arg::with_name("verbosity")
                .help("Sets verbosity for program logging output.")
                .short("v")
                .long("verbosity")
                .multiple(true)
                .takes_value(false)
                .required(false)
        )
        .get_matches();


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

    // determine trace mode of operation
    let mode = matches.value_of("trace_mode").unwrap();
    info!("Utilizing trace mode: {}", mode);
    let trace_mode = TraceProc::get_handler(mode);

    // parse out policy generation options
    let policy_path = matches.value_of("policy_path")
        .map(|p| PathBuf::from(p));

    // initialize TraceProc interface
    info!("Starting up TraceProc instantiation");
    let mut proc = TraceProc::new(trace_mode)
        .trace_config(matches.is_present("json"))
        .policy_config(policy_path);

    // run trace depending on arguments specified
    info!("Executing a trace with process handler");
    if let Err(e) = proc.run_trace(args, true) {
        eprintln!("confine exception: {}", e);
        eprintln!("{}", e.backtrace());
    }
}
