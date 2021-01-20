//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;

use clap::{App, Arg};

use confine::config::Configuration;
use confine::trace::Tracer;

/// Takes an initialized `TraceProc` and execute a normal trace, and store to struct. Once traced,
/// we can preemptively output the trace as well, in the case the user only wants a trace.
fn run_trace(config: Configuration, verbose_trace: bool) -> Result<(), Box<dyn Error>> {
    // instantiate a new dynamic tracer, optionally with a policy path
    //let mut tracer: Tracer = Tracer::new(args, policy, verbose_trace)?;

    // execute trace with the given executable, output syscalls if `verbose_trace` is set
    //tracer.trace()?;
    Ok(())
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("PATH")
                .help("Path to configuration for provisioning container.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("verbose_trace")
                .help("Runs and output a standard trace against syscalls during execution.")
                .short("v")
                .long("verbose_trace")
                .required(false),
        )
        .get_matches();

    // get path to configuration to provision and execute
    let config_path: PathBuf = PathBuf::from(matches.value_of("PATH").unwrap());

    // parse configuration from path
    let configuration: Configuration =
        Configuration::new(config_path).expect("Unable to parse configuration.");

    // check if we are only running a simple trace
    let verbose_trace: bool = matches.is_present("verbose_trace");

    // run trace depending on arguments specified
    if let Err(err) = run_trace(configuration, verbose_trace) {
        eprintln!("confine exception: {}", err);
    }
}
