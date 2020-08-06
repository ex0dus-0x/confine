//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::boxed::Box;
use std::path::PathBuf;

use clap::{App, Arg};

use log::{log, LevelFilter};
use log::{debug, warn, fail, info};


use confine::enforcers::Enforcer;
use confine::logger::TraceLogger;
use confine::policy::PolicyInterface;
use confine::trace::Tracer;

static LOGGER: TraceLogger = TraceLogger;

/// `TraceProc` provides an interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
#[derive(Default)]
struct TraceProc {
    tracer: Tracer,
    policy: Option<PolicyInterface>,
    json: bool,
}

impl TraceProc {
    /// `new()` initializes a new TraceProc interface with default attributes. Expects developer to build up struct
    /// with following builder methods.
    pub fn new(_policy: Option<PathBuf>, json: bool) -> Self {
        // instantiates policy interface if file is given
        let policy: Option<PolicyInterface> = match _policy {
            Some(pol) => match PolicyInterface::new_policy(pol) {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            n => n,
        };

        // instantiate new tracer
        let tracer: Tracer = Tracer::new();

        Self {
            tracer,
            policy,
            json,
        }
    }

    /// takes an initialized `TraceProc` and execute a normal trace, and store to struct. Once traced,
    /// we can preemptively output the trace as well, in the case the user only wants a trace.
    fn run_trace(
        &mut self,
        args: Vec<String>,
        output: bool,
        gen_profile: bool,
    ) -> Result<(), Error> {
        let table = Some(self.tracer.trace(args)?);
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
    let matches = App::new(env!("CRATE_NAME"))
        .about(env!("CRATE_DESCRIPTION"))
        .arg(
            Arg::with_name("COMMAND")
                .help("Command to run under sandboxing, including any positional arguments")
                .raw(true)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("policy_path")
                .help("Path to policy file to parse and enforce on the command being run")
                .short("p")
                .long("policy")
                .takes_value(true)
                .value_name("POLICY_PATH")
                .required(false),
        )
        .arg(
            Arg::with_name("generate_profile")
                .help("If policy if set, generate a profile from enforcer")
                .short("g")
                .long("generate")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("json")
                .help("Output system call trace as JSON.")
                .short("j")
                .long("json")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("verbosity")
                .help("Sets verbosity for program logging output.")
                .short("v")
                .long("verbosity")
                .multiple(true)
                .takes_value(false)
                .required(false),
        )
        .get_matches();

    // initialize logger with basic logging levels
    let level_filter = match matches.occurrences_of("verbosity") {
        2 => LevelFilter::Debug,
        1 => LevelFilter::Info,
        0 | _ => LevelFilter::Off,
    };
    log::set_logger(&LOGGER).expect("unable to initialize logger");
    log::set_max_level(level_filter);
    info!("Initialized logger");

    // collect args into vec and convert to String for lifetime
    let _args: Vec<&str> = matches.values_of("COMMAND").unwrap().collect::<Vec<&str>>();
    let args: Vec<String> = _args.iter().map(|s| s.to_string()).collect();

    debug!("Command and arguments: {:?}", args);

    // parse out policy generation options
    let policy_path: Option<PathBuf> = matches
        .value_of("policy_path")
        .map_or(None, |p| Some(PathBuf::from(p)));
    info!("Using input policy path: {:?}", policy_path);

    // json configuration
    let json: bool = matches.is_present("json");

    // initialize TraceProc interface
    info!("Starting up TraceProc instantiation");
    let mut proc = TraceProc::new(policy_path, json);

    // check for presence of flag to generate profile
    // NOTE: this is ignored if no policy path is specified
    let generate_profile: bool = matches.is_present("generate_profile");

    // run trace depending on arguments specified
    info!("Executing confined trace with process handler");
    if let Err(e) = proc.run_trace(args, true, generate_profile) {
        eprintln!("confine exception: {} {}", e, e.backtrace());
    }
}
