//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;

use clap::{App, AppSettings, Arg};

mod config;
mod error;
mod syscall;
mod threat;
mod trace;

use crate::config::Confinement;
use crate::trace::Tracer;

fn run_trace(config: Confinement, verbose_trace: bool) -> Result<(), Box<dyn Error>> {
    // create a new dynamic tracer, optionally with a policy path
    let mut tracer: Tracer = Tracer::new(config, verbose_trace)?;

    // execute trace with the given executable, output syscalls if `verbose_trace` is set
    //tracer.trace()?;
    Ok(())
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(
            Arg::with_name("PATH")
                .help("Path to workspace with `Confinement` for provisioning container.")
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
    let mut config_path: PathBuf = PathBuf::from(matches.value_of("PATH").unwrap());
    config_path.push("Confinement");
    if !config_path.exists() {
        panic!(
            "Path containing `Confinement` doesn't exist: {:?}.",
            config_path
        );
    }

    // parse configuration from path
    let config: Confinement = match Confinement::new(config_path) {
        Ok(config) => config,
        Err(e) => {
            panic!("{}", e);
        }
    };

    // check if we are only running a simple trace
    let verbose_trace: bool = matches.is_present("verbose_trace");

    // run trace depending on arguments specified
    if let Err(err) = run_trace(config, verbose_trace) {
        panic!("confine exception: {}", err);
    }
}
