//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;

use clap::{App, Arg};

use confine::policy::Policy;
use confine::trace::Tracer;

/// Takes an initialized `TraceProc` and execute a normal trace, and store to struct. Once traced,
/// we can preemptively output the trace as well, in the case the user only wants a trace.
fn run_trace(
    args: Vec<String>,
    policy: Option<Policy>,
    verbose_trace: bool,
) -> Result<(), Box<dyn Error>> {
    // instantiate a new dynamic tracer, optionally with a policy path
    let mut tracer: Tracer = Tracer::new(args, policy, verbose_trace)?;

    // execute trace with the given executable, output syscalls if `verbose_trace` is set
    tracer.trace()?;
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
                .required(false),
        )
        .arg(
            Arg::with_name("policy_path")
                .help("Path to policy file to parse and enforce on the command being run.")
                .short("p")
                .long("policy")
                .takes_value(true)
                .value_name("POLICY_PATH")
                .required(false),
        )
        .arg(
            Arg::with_name("verbose_trace")
                .help("Runs and output a standard trace against syscalls during execution.")
                .short("v")
                .long("verbose_trace")
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
    let verbose_trace: bool = matches.is_present("verbose_trace");

    // run trace depending on arguments specified
    if let Err(e) = run_trace(args, policy, verbose_trace) {
        eprintln!("confine exception: {}", e);
    }
}
