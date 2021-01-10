//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;

use clap::{App, Arg};

use confine::policy::PolicyInterface;
use confine::trace::Tracer;

/// Provides an interface for initializing and interacting with a specified PID. It implements
/// internal controls and establishes helpers for syscalls that are needed for tracer/tracee interactions.
#[derive(Default)]
struct TraceProc {
    tracer: Tracer,
    policy: Option<PolicyInterface>,
}

impl TraceProc {
    /// Initialize a new TraceProc interface with default attributes for use with builder methods
    pub fn new(_policy: Option<PathBuf>) -> Self {
        // instantiates policy interface if file is given
        let policy: Option<PolicyInterface> = match _policy {
            Some(pol) => match PolicyInterface::new_policy(pol) {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            None => None,
        };

        Self {
            tracer: Tracer::new(),
            policy,
        }
    }

    // TODO: deal with policy

    /// Takes an initialized `TraceProc` and execute a normal trace, and store to struct. Once traced,
    /// we can preemptively output the trace as well, in the case the user only wants a trace.
    pub fn run_trace(&mut self, args: Vec<String>, trace_only: bool) -> Result<(), Box<dyn Error>> {
        let table = Some(self.tracer.trace(args)?);
        if trace_only {
            println!("{}", table.unwrap().json_out()?);
        }
        Ok(())
    }
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
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
            Arg::with_name("trace_only")
                .help("Run only a standard trace against syscalls")
                .short("t")
                .long("trace_only")
                .required(false),
        )
        .get_matches();

    // collect args into vec and convert to String for lifetime
    let _args: Vec<&str> = matches.values_of("COMMAND").unwrap().collect::<Vec<&str>>();
    let args: Vec<String> = _args.iter().map(|s| s.to_string()).collect();

    // parse out policy generation options
    let policy_path: Option<PathBuf> = matches.value_of("policy_path").map(|p| PathBuf::from(p));

    // initialize TraceProc interface
    let mut proc = TraceProc::new(policy_path);

    // check if we are only running a simple trace
    let trace_only: bool = matches.is_present("trace_only");

    // run trace depending on arguments specified
    if let Err(e) = proc.run_trace(args, trace_only) {
        eprintln!("confine exception: {:?}", e);
    }
}
