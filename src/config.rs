//! Defines the `Confinement` policy format for provisioning container environments for dynamic
//! malware analysis.
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::ConfineResult;
use crate::policy::Policy;
use crate::syscall::ParsedSyscall;

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
        Ok(Some(_))
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

/// Declares an action parsed by the userspace application and applied to
/// system calls before trace.
#[derive(Debug, Clone)]
pub enum Action {
    Permit, // enable execution of system call
    Warn,   // warns user through STDOUT, but continue trace
    Block,  // SIGINT to trace execution when encountering call
    Log,    // log syscall execution to log
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = Deserialize::deserialize(deserializer)?;
        let action: Self = match raw.as_str() {
            "Warn" | "WARN" => Action::Warn,
            "Block" | "BLOCK" => Action::Block,
            "Log" | "LOG" => Action::Log,
            _ => Action::Permit,
        };
        Ok(action)
    }
}

/// Wrapper around a syscall rule that gets added to our policy map.
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub syscall: String,
    pub action: Action,
}

// Represents a parsed policy configuration used for enforcing against the trace.
#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    // if set, defines a path where syscalls are logged to
    pub logpath: Option<PathBuf>,

    // all rules that are to be enforced during dynamic tracing
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Checks if a given syscall name is set as a rule, and return action to enforce if found.
    pub fn get_enforcement(&self, syscall: &str) -> Option<Action> {
        self.rules
            .iter()
            .find(|rule| rule.syscall == syscall)
            .map(|rule| rule.action.clone())
    }

    /// Enforces a LOG rule by writing to the specified input file the full system call that is
    /// marked to be logged.
    pub fn to_log(&self, syscall: ParsedSyscall) -> ConfineResult<()> {
        if let Some(path) = &self.logpath {
            fs::write(path, syscall.to_string()?)?;
        }
        Ok(())
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
