//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;

use clap::{App, Arg};

use confine::policy::Policy;
use confine::trace::Tracer;

/// Takes an initialized `TraceProc` and execute a normal trace, and store to struct. Once traced,
/// we can preemptively output the trace as well, in the case the user only wants a trace.
fn run_trace(
    args: Vec<String>,
    policy: Option<Policy>,
    trace_only: bool,
) -> Result<(), Box<dyn Error>> {
    // instantiate a new dynamic tracer, optionally with a policy path
    let mut tracer: Tracer = Tracer::new(args, policy)?;

    // execute trace with the given executable
    tracer.trace()?;

    // block before output
    let duration = Duration::new(1, 0);
    thread::sleep(duration);

    // output a normal but full trace if `trace_only` is specified, otherwise give a briefer trace
    // but with threat analytics
    if trace_only {
        println!("{}", tracer.normal_trace()?);
    } else {
        println!("{}", tracer.threat_trace()?);
    }
    Ok(())
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
                .help("Run only a standard trace against syscalls, and output JSONified trace.")
                .short("t")
                .long("trace_only")
                .required(false),
        )
        .get_matches();

    // collect args into vec and convert to String for lifetime
    let _args: Vec<&str> = matches.values_of("COMMAND").unwrap().collect::<Vec<&str>>();
    let args: Vec<String> = _args.iter().map(|s| s.to_string()).collect();

    // TODO: canonicalize the actual application, unshare only supports abspaths and not $PATH

    // parse out policy generation options
    #[allow(clippy::redundant_closure)]
    let policy_path: Option<PathBuf> = matches.value_of("policy_path").map(|p| PathBuf::from(p));

    // instantiates policy interface if file is given
    let policy: Option<Policy> = match policy_path {
        Some(pol) => match Policy::new(pol) {
            Ok(p) => Some(p),
            Err(_) => None,
        },
        None => None,
    };

    // check if we are only running a simple trace
    let trace_only: bool = matches.is_present("trace_only");

    // run trace depending on arguments specified
    if let Err(e) = run_trace(args, policy, trace_only) {
        eprintln!("confine exception: {}", e);
    }
}
