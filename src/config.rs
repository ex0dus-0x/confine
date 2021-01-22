//! Defines the `Confinement` policy format for provisioning container environments for dynamic
//! malware analysis.
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::ConfineResult;
use crate::policy::Policy;

/// Defines the root of a Confinement configuration that gets parsed out from a given path that
/// bootstraps the analysis of an executable sample.
#[derive(Deserialize, Debug, Clone)]
pub struct Confinement {
    // metadata about the target sample being analyzed
    pub sample: Sample,

    // optional policy for enforcement
    pub policy: Option<Policy>,

    // defines workflow steps necessary to execute environment with sample
    pub execution: Vec<Step>,
}

impl Confinement {
    /// Given a yaml configuration, create the strongly typed interface to parse for when
    /// bootstrapping the tracing environment.
    pub fn new(path: PathBuf) -> ConfineResult<Self> {
        let contents: String = fs::read_to_string(path)?;
        let yaml = serde_yaml::from_str(&contents)?;
        Ok(yaml)
    }

    /// If called, pulls down the malware sample to the (assuming containerized) system if the
    /// developer included a `url` parameter in segment.
    pub fn pull_sample(&self) -> ConfineResult<Option<()>> {
        // return immediately if no url is specified
        if !self.sample.contains_url() {
            return Ok(None);
        }

        // otherwise download file to container
        Ok(Some(()))
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

impl Sample {
    pub fn contains_url(&self) -> bool {
        self.url.is_some()
    }
}

/// Defines sequential step executed in the container to properly setup the environment for
/// dynamic tracing. Useful if sample needs to be compiled, or there are extra steps to extrapolate
/// it from upstream.
#[derive(Deserialize, Debug, Clone)]
pub struct Step {
    // name identifier for the step
    name: String,

    // if set, dynamic tracing will occur during this step and output capabilities report
    trace: Option<bool>,

    // space seperated vector containing all components of the command to run
    command: Vec<String>,
}
