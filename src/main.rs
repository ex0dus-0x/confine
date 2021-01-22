//! CLI interface for confine library modules. Implements tracing under two
//! different modes, and provides deserialization support to serializable formats.

use std::error::Error;
use std::path::PathBuf;

use clap::{App, AppSettings, Arg};

mod config;
mod container;
mod error;
mod policy;
mod syscall;
mod threat;
mod trace;

use crate::config::Confinement;
use crate::trace::Tracer;

fn run_trace(config: Confinement) -> Result<(), Box<dyn Error>> {
    let mut tracer: Tracer = Tracer::new(config)?;
    tracer.run()?;
    Ok(())
}

fn main() {
    pretty_env_logger::init();
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
        // TODO: specify own mountpoint
        .get_matches();

    // get path to configuration to provision and execute
    log::trace!("Checking path to `Confinement` configuration");
    let mut config_path: PathBuf = PathBuf::from(matches.value_of("PATH").unwrap());
    config_path.push("Confinement");
    if !config_path.exists() {
        log::error!(
            "Path containing `Confinement` doesn't exist: {:?}.",
            config_path
        );
    }

    // parse configuration from path
    log::trace!("Parsing `Confinement` configuration");
    let config: Confinement = match Confinement::new(config_path) {
        Ok(config) => config,
        Err(err) => {
            log::error!("{}", err);
            std::process::exit(-1);
        }
    };

    // run trace depending on arguments specified
    if let Err(err) = run_trace(config) {
        log::error!("{}", err);
    }
}
