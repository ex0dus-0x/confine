use std::error::Error;
use std::path::PathBuf;

use clap::{App, AppSettings, Arg, ArgMatches};

mod config;
mod container;
mod error;
mod policy;
mod syscall;
mod threat;
mod trace;

use crate::config::Confinement;
use crate::trace::Tracer;

fn main() {
    let cli_args: ArgMatches = parse_args();
    if let Err(err) = run(cli_args) {
        log::error!("{}", err);
        std::process::exit(-1);
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new(env!("CARGO_PKG_NAME"))
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
            Arg::with_name("mount")
                .help("Override mountpoint for custom rootfs instead of default Alpine.")
                .long("mount")
                .takes_value(true)
                .value_name("ROOTFS")
                .required(false),
        )
        .arg(
            Arg::with_name("hostname")
                .help("Set container hostname instead of randomly generating one.")
                .long("hostname")
                .takes_value(true)
                .value_name("HOSTNAME")
                .required(false),
        )
        .get_matches()
}

fn run(matches: ArgMatches) -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

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

    // other flags
    let rootfs: Option<&str> = matches.value_of("mount");
    let hostname: Option<&str> = matches.value_of("hostname");

    log::info!("Starting new containerized tracer...");
    let mut tracer: Tracer = Tracer::new(config, rootfs, hostname)?;
    tracer.run()?;
    Ok(())
}
