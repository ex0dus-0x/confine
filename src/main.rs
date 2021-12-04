use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use log::LevelFilter;

use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use redbpf::load::Loader;
use futures::stream::StreamExt;

use std::{ffi::CStr, ptr};

// TODO:
//use confine_probes::tracer::OpenPath;

mod container;
mod error;
mod policy;
mod syscall;
mod threat;
mod trace;

use crate::policy::{Confinement, Policy};
use crate::trace::Tracer;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct OpenPath {
    pub filename: [u8; 256],
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/tracer/tracer.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");
    for kp in loaded.kprobes_mut() {
        kp.attach_kprobe(&kp.name(), 0)
            .expect(&format!("error attaching kprobe program {}", kp.name()));
    }

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "OPEN_PATHS" {
            for event in events {
                let open_path = unsafe { ptr::read(event.as_ptr() as *const OpenPath) };
                unsafe {
                    let cfilename = CStr::from_ptr(open_path.filename.as_ptr() as *const _);
                    println!("{}", cfilename.to_string_lossy());
                };
            }
        }
    }

}

/*
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
                .about("Nukes a given workspace.")
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

        log::trace!("Writing default template to Confinement");
        let confinement = serde_yaml::to_string(&Confinement::default())?;
        fs::write(&config_path, confinement)?;

        println!(
            "Done! Your new workspace is created. Edit your configuration at `{}`",
            config_path.to_str().unwrap()
        );
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

        print!("Are you sure you want to delete this workspace? There's no going back! (y/N) ");
        io::stdout().flush()?;

        let mut input = String::new();
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        handle.read_line(&mut input)?;

        match input.as_str() {
            "y" | "Y" | "yes" | "Yes" => {
                log::trace!("Deleting the workspace");
                fs::remove_dir_all(config_path)?;
                println!("Destroyed the workspace! Bye bye malware!");
            }
            _ => {}
        }
    }
    Ok(())
}
*/
