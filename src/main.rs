use std::fs::{self, File};
use std::process;
use std::error::Error;
use std::path::PathBuf;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use log::LevelFilter;

mod container;
mod error;
mod policy;
mod syscall;
mod threat;
mod trace;

use crate::policy::Policy;
use crate::trace::Tracer;

fn main() {
    env_logger::init();
    let cli_args: ArgMatches = parse_args();
    if let Err(err) = run(cli_args) {
        log::error!("{}", err);
        process::exit(-1);
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    let path_arg = Arg::with_name("PATH")
        .help("Name of workspace path to interact with.")
        .takes_value(true)
        .required(true);

    App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new")
                .about("Creates a new workspace with a Confinement policy for configuring.")
                .arg(&path_arg),
        )
        .subcommand(
            SubCommand::with_name("exec")
                .about("Starts dynamic analysis on target workspace.")
                .arg(&path_arg),
        )
        .subcommand(
            SubCommand::with_name("destruct")
                .about("Nukes a given workspace and")
                .arg(&path_arg),
        )
        .arg(
            Arg::with_name("verbosity")
                .help("Sets the level of verbosity used.")
                .short("v")
                .multiple(true)
                .takes_value(false)
                .required(false),
        )
        .get_matches()
}

fn run(matches: ArgMatches) -> Result<(), Box<dyn Error>> {
    let loglevel = match matches.occurrences_of("verbosity") {
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        3 => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };
    log::set_max_level(loglevel);

    // check the command being run
    if let Some(args) = matches.subcommand_matches("new") {
        log::trace!("Checking if workspace already exists");
        let mut config_path: PathBuf = PathBuf::from(args.value_of("PATH").unwrap());
        if config_path.exists() {
            log::error!("Workspace {:?} specified already exists.", config_path);
            process::exit(-1);
        }

        log::trace!("Creating the workspace");
        fs::create_dir(&config_path)?;
        
        log::trace!("Creating new default Confinement");
        config_path.push("Confinement");
        File::create(&config_path)?;

    } else if let Some(args) = matches.subcommand_matches("exec") {
        log::trace!("Checking path to Confinement");
        let mut config_path: PathBuf = PathBuf::from(args.value_of("PATH").unwrap());
        config_path.push("Confinement");
        if !config_path.exists() {
            log::error!(
                "Path containing Confinement doesn't exist: {:?}.",
                config_path
            );
            process::exit(-1);
        }

        log::trace!("Parsing Confinement policy");
        let config: Policy = Policy::new(config_path)?;

        log::info!("Starting new containerized tracer...");
        let mut tracer: Tracer = Tracer::new(config)?;
        tracer.run()?;

    } else if let Some(args) = matches.subcommand_matches("destruct") {
        log::trace!("Checking if workspace doesn't exist");
        let mut config_path: PathBuf = PathBuf::from(args.value_of("PATH").unwrap());
        config_path.push("Confinement");
        if !config_path.exists() {
            log::error!("Workspace {:?} doesn't exist.", config_path);
            process::exit(-1);
        }

        // ASK FOR CONFIRMATION!!

        log::trace!("Deleting the workspace");
        fs::remove_dir_all(config_path)?;
    }
    Ok(())
}
