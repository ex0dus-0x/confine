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
    fn policy_config(mut self, _policy: Option<PathBuf>) -> Self {
        if let Some(policy) = _policy {
            self.policy = match PolicyInterface::new_policy(policy) {
                Ok(_policy) => Some(_policy),
                Err(_) => None,
            };
        }
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
    fn run_trace(&mut self, args: Vec<String>, output: bool, gen_profile: bool) -> Result<(), Error> {
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
}



#[allow(unused_must_use)]
fn main() {
    let matches = App::new("confine")
        .about("security-focused process tracer with policy handling capabilities")
        .author("ex0dus-0x <ex0dus at codemuch.tech>")
        .arg(
            Arg::with_name("command")
                .help("Command to analyze as child, including positional arguments")
                .raw(true)
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("policy_path")
                .help("Path to policy file to use for enforcement")
                .short("p")
                .long("policy")
                .takes_value(true)
                .value_name("POLICY_PATH")
                .required(false)
        )
        .arg(
            Arg::with_name("generate_profile")
                .help("If policy if set, generate a profile from enforcer")
                .short("g")
                .long("generate")
                .takes_value(false)
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
    let policy_path: Option<PathBuf> = matches.value_of("policy_path")
        .map_or(None, |p| Some(PathBuf::from(p)));
    info!("Using input policy path: {:?}", policy_path);

    // initialize TraceProc interface
    info!("Starting up TraceProc instantiation");
    let mut proc = TraceProc::new()
        .policy_config(policy_path)
        .trace_handler(mode)
        .out_json(matches.is_present("json"));

    // check for presence of flag to generate profile
    // NOTE: this is ignored if no policy path is specified
    let generate_profile: bool = matches.is_present("generate_profile");

    // run trace depending on arguments specified
    info!("Executing confined trace with process handler");
    if let Err(e) = proc.run_trace(args, true, generate_profile) {
        eprintln!("confine exception: {} {}", e, e.backtrace());
    }
}
