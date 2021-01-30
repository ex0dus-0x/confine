//! Defines the `Confinement` policy format for provisioning container environments for dynamic
//! malware analysis.
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;

pub mod filter;

use crate::error::ConfineResult;
use crate::policy::filter::Filter;

/// Provides an interface for parsing a `Confinement` from a given workspace
pub struct Policy {
    // stores path to workspace with `Confinement`, used later to read out other resources
    workspace: PathBuf,

    // stores parsed Confinement
    pub config: Confinement,
}

impl Policy {
    pub fn new(config_path: PathBuf) -> ConfineResult<Self> {
        let config: Confinement = Confinement::new(&config_path)?;

        // check if workspace directory exists
        let workspace = match config_path.parent() {
            Some(dir) => dir.to_path_buf(),
            None => unreachable!(),
        };

        Ok(Self {
            workspace,
            config
        })
    }

    /// If called, pulls down the malware sample to the current workspace if the
    /// developer included a `url` parameter in segment.
    pub fn pull_sample(&self) -> ConfineResult<Option<()>> {
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

            log::trace!("Writing to current path");
            
        }
        Ok(Some(()))
    }

    /// Copies all the paths from the workspace to the current path, most likely the tmpdir
    /// created for the rootfs mount.
    pub fn copy_workspace(&self) -> ConfineResult<()> {
        Ok(())
    }

    /// Getter for configuration execution steps
    pub fn get_exec(&self) -> Vec<Step> {
        self.config.execution.clone()
    }

    /// Getter for syscall filter
    pub fn get_filter(&self) -> Option<Filter> {
        self.config.filter.clone()
    }
}


/// Defines the root of a Confinement configuration that gets parsed out from a given path that
/// bootstraps the analysis of an executable sample.
#[derive(Deserialize, Debug, Clone)]
pub struct Confinement {
    // metadata about the target sample being analyzed
    pub sample: Sample,

    // optional syscall filters for enforcement
    pub filter: Option<Filter>,

    // defines workflow steps necessary to execute environment with sample
    pub execution: Vec<Step>,
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
/// upstream from some dataset, or if it needs to be build
#[derive(Deserialize, Debug, Clone)]
pub struct Sample {
    // name of target being analyzed
    name: String,

    // optional description about the sample
    description: Option<String>,

    // optional URL to denote upstream path to sample, which can be furthered processed
    url: Option<String>,
}

/// Defines sequential step executed in the container to properly setup the environment for
/// dynamic tracing. Useful if sample needs to be compiled, or there are extra steps to extrapolate
/// it from upstream.
#[derive(Deserialize, Debug, Clone)]
pub struct Step {
    // name identifier for the step
    pub name: String,

    // if set, dynamic tracing will occur during this step and output capabilities report
    pub trace: Option<bool>,

    // space seperated vector containing all components of the command to run
    pub command: Vec<String>,
}
