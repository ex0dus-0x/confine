//! Defines the `Confinement` policy format for provisioning container environments for dynamic
//! malware analysis.
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod filter;

use crate::error::ConfineResult;
use crate::policy::filter::Filter;

/// Provides an interface for parsing a `Confinement` from a given workspace, and copying over
/// the workspace directory state over to the rootfs
pub struct Policy {
    // stores path to workspace with `Confinement`, used later to read out other resources
    pub workspace: PathBuf,

    // stores parsed Confinement
    pub config: Confinement,
}

impl Policy {
    pub fn new(config_path: PathBuf) -> ConfineResult<Self> {
        let config: Confinement = Confinement::new(&config_path)?;

        // get parent as workspace path
        let workspace = match config_path.parent() {
            Some(dir) => dir.to_path_buf(),
            None => unreachable!(),
        };

        Ok(Self {
            workspace: fs::canonicalize(&workspace)?,
            config,
        })
    }

    /// If called, pulls down the malware sample to the current workspace if the
    /// developer included a `url` parameter in segment.
    pub fn pull_sample(&self, to: &PathBuf) -> ConfineResult<Option<()>> {
        // return immediately if no url is specified
        if self.config.sample.url.is_none() {
            return Ok(None);

        // download to current path if set
        } else if let Some(url) = &self.config.sample.url {
            log::trace!("Sending request to pull upstream sample from {}", url);
            let resp = ureq::get(&url).call()?;

            let len = resp
                .header("Content-Length")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap();

            log::trace!("Reading {} bytes of content from response", len);
            let mut malware_sample: Vec<u8> = Vec::with_capacity(len);
            resp.into_reader().read_to_end(&mut malware_sample)?;

            let write_path: PathBuf = to.join("suspicious.sample");
            log::trace!("Writing to directory specified: {:?}", write_path);
            fs::write(&write_path, &malware_sample)?;
        }
        Ok(Some(()))
    }

    /// Getter for hostname
    pub fn get_hostname(&self) -> Option<String> {
        self.config.sample.hostname.clone()
    }

    /// Getter for persistent mountpath
    pub fn get_mountpath(&self) -> Option<String> {
        self.config.sample.image.clone()
    }

    /// Getter for configuration setup steps to run before containerization.
    pub fn get_setup(&self) -> Option<Vec<Step>> {
        self.config.provision.setup.clone()
    }

    /// Getter for configuration execution steps to run during containerization.
    pub fn get_exec(&self) -> Vec<Step> {
        self.config.provision.execution.clone()
    }

    /// Getter for syscall filter for enforcement during tracing.
    pub fn get_filter(&self) -> Option<Filter> {
        self.config.filter.clone()
    }
}

/// Defines the root of a Confinement configuration that gets parsed out from a given path that
/// bootstraps the analysis of an executable sample.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Confinement {
    // metadata about the target sample being analyzed
    pub sample: Sample,

    // optional syscall filters for enforcement
    pub filter: Option<Filter>,

    // defines setup and execution steps
    pub provision: Provision,
}

impl Confinement {
    /// Given a yaml configuration, create the strongly typed interface to parse for when
    /// bootstrapping the tracing environment.
    pub fn new(path: &PathBuf) -> ConfineResult<Self> {
        let contents: String = fs::read_to_string(path)?;
        let yaml = serde_yaml::from_str(&contents)?;
        Ok(yaml)
    }
}

/// Provides a definition into the sample that is to be traced or processed, whether it exists
/// upstream from some dataset, or if it needs to be build.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Sample {
    // name of target being analyzed
    name: String,

    // optional path to the mountpoint (WIP: support pulling Docker builds)
    image: Option<String>,

    // optional configured hostname, otherwise will be randomly generated
    hostname: Option<String>,

    // optional URL to denote upstream path to sample, which can be furthered processed
    url: Option<String>,
}

/// Defines sequential steps executed in the container to properly setup the environment.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Provision {
    // optional setup stage to execute before initializing environment
    pub setup: Option<Vec<Step>>,

    // defines workflow steps necessary to execute environment with sample
    pub execution: Vec<Step>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Step {
    // optional name identifier for the step
    pub name: String,

    // if set, dynamic tracing will occur during this step and output capabilities report
    pub trace: Option<bool>,

    // space seperated vector containing all components of the command to run
    pub command: Vec<String>,
}
