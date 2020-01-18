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

use confine::logger::TraceLogger;
use confine::policy::PolicyInterface;
use confine::enforcers::Enforcer;
use confine::trace::{ProcessHandler, Ptrace, Ebpf};


static LOGGER: TraceLogger = TraceLogger;


/// `TraceProc` provides a builder interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
struct TraceProc {
    mode: Box<dyn ProcessHandler>,
    json: bool,
    policy: Option<PolicyInterface>,
}

impl Default for TraceProc {
    fn default() -> Self {
        Self {
            mode: Box::new(Ptrace::new()),
            json: false,
            policy: None
        }
    }
}


impl TraceProc {

    /// `new()` initializes a new TraceProc interface with default attributes. Expects developer to build up struct
    /// with following builder methods.
    fn new() -> Self {
        Self::default()
    }


    /// `_parse_handler()` is a factory-like helper method that returns a trait object that represents the instance
    /// of a struct that satisfies the ProcessHandler trait bound.
    #[inline]
    fn _parse_handler(handler_str: &str) -> Box<dyn ProcessHandler + 'static> {
        match handler_str {
            "ptrace" => Box::new(Ptrace::new()),
            "ebpf" => Box::new(Ebpf::new()),
            _ => unreachable!()
        }
    }


    /// `trace_handler()` builds up TraceProc by parsing a user-specified handler input and instantiating the appropriate
    /// one that implements the ProcessHandler trait bound.
    fn trace_handler(mut self, handler_str: &str) -> Self {
        self.mode = Self::_parse_handler(handler_str);
        self
    }


    /// `policy_config()` builds up TraceProc by parsing in a common confine policy and a specified
    /// output policy enforcer format (ie seccomp, apparmor)
    fn policy_config(mut self, policy: PathBuf, /*_enforcer: Option<Box<dyn Enforcer>>*/) -> Self {
        self.policy = match PolicyInterface::new_policy(policy) {
            Ok(_policy) => Some(_policy),
            Err(_) => None,
        };
        self
    }


    /// `out_json()` builds up and configures TraceProc to output json after trace.
    /// TODO: should be enhanced in order to consume various serde-compatible file formats.
    fn out_json(mut self, json: bool) -> Self {
        self.json = json;
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
        // TODO: check if policy_path is set
        if let None = self.policy {
            unimplemented!()
        }

        self.run_trace(args, output)?;
        Ok(())
    }


    /// `generate_enforce_profile()` takes a parsed confine policy and generates a
    /// profile for an enforcer module, and returns a path to write.
    fn generate_enforce_profile(&self, output: PathBuf) -> () {
        unimplemented!()
    }
}


#[allow(unused_must_use)]
fn main() {
    let matches = App::new("confine")
        .about("security-focused process tracer with policy handling capabilities")
        .author("ex0dus-0x <ex0dus at codemuch.tech>")
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

    // parse out policy generation options
    let policy_path = matches.value_of("policy_path")
        .map(|p| PathBuf::from(p)).unwrap();
    info!("Using input policy path: {:?}", policy_path);

    // initialize TraceProc interface
    info!("Starting up TraceProc instantiation");
    let mut proc = TraceProc::new()
        .trace_handler(mode)
        .policy_config(policy_path)
        .out_json(matches.is_present("json"));

    // run trace depending on arguments specified
    if !matches.is_present("policy_path") {
        info!("Executing a normal trace with process handler");
        if let Err(e) = proc.run_trace(args, true) {
            eprintln!("confine exception: {}", e);
            eprintln!("{}", e.backtrace());
        }
    } else if matches.is_present("policy_path") {
        info!("Executing a trace with a specified policy file");
        if let Err(e) = proc.run_trace_policy(args, true) {
            eprintln!("confine exception: {}", e);
            eprintln!("{}", e.backtrace());
        }
    }
}
