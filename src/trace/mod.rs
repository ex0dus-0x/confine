//! Defines the main debugr that is interfaced against for execution of a configuration.
use nix::sys::signal::Signal;
use nix::sched;
use nix::mount::{self, MsFlags};
use nix::sys::wait;

use std::process::Command;

mod subprocess;

use crate::config::Confinement;
use crate::container::Container;
use crate::error::ConfineResult;
use crate::trace::subprocess::Subprocess;

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // configuration to be used during tracing
    config: Confinement,

    // container interface
    runtime: Container,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(
        config: Confinement,
        rootfs: Option<&str>,
        hostname: Option<&str>,
    ) -> ConfineResult<Self> {
        Ok(Self {
            config,
            runtime: Container::init(rootfs, hostname)?,
        })
    }

    /// Encapsulates container runtime creation and process tracing execution under a callback that
    /// is cloned to run.
    pub fn run(&mut self) -> ConfineResult<()> {

        // prevent mounting container fs to host
        mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )?; 

        // initialize child process stack
        let stack = &mut [0; 1024 * 1024];

        // create function callback for cloning, with error-handling
        let callback = Box::new(|| {
            if let Err(e) = self.exec_container_debug() {
                log::error!("{}", e);
                -1
            } else {
                0
            }
        });

        // set namespaces to unshare for the new process
        let clone_flags = sched::CloneFlags::CLONE_NEWNS
            | sched::CloneFlags::CLONE_NEWPID
            | sched::CloneFlags::CLONE_NEWCGROUP
            | sched::CloneFlags::CLONE_NEWUTS
            | sched::CloneFlags::CLONE_NEWIPC
            | sched::CloneFlags::CLONE_NEWNET;

        // clone new process with callback
        log::trace!("Cloning new process with unshared namespaces");
        let child = sched::clone(callback, stack, clone_flags, Some(Signal::SIGCHLD as i32))?;

        // wait for child to finish execution
        log::debug!("Waiting for process to complete");
        wait::waitpid(child, None)?;
        Ok(())
    }

    /// Executes a dynamic `pdebug`-based debug upon the given application specified. Will first
    /// instantiate a containerized environment with unshared namespaces and a seperately mounted
    /// filesystem, and then spawn the debuge.
    fn exec_container_debug(&mut self) -> ConfineResult<isize> {
        // create the container environment to execute processes under
        log::trace!("Starting container");
        self.runtime.start()?;

        // pull malware sample to container if `url` is set for config
        if self.config.pull_sample()?.is_some() {
            log::info!("Pulling down malware sample from upstream source...");
        }

        // execute each step, creating a `Subprocess` for those that are marked to be debugd
        log::info!("Executing steps...");
        for (idx, step) in self.config.execution.iter().enumerate() {
            let cmd: Vec<String> = step.command.clone();
            if let Some(true) = step.trace {
                log::info!("Running traced step {}: `{}`...", idx + 1, step.name);
                let mut sb: Subprocess = Subprocess::new(cmd, self.config.policy.clone())?;

                log::debug!("Starting trace of the child");
                sb.trace()?;

                // once done, output capabilities debug
                log::debug!("Outputting threat report");
                println!("{}", sb.threat_trace()?);
            } else {
                log::info!("Running un-traced step {}: `{}`...", idx + 1, step.name);
                let mut exec: Command = Command::new(&cmd[0]);
                for arg in cmd.iter().skip(1) {
                    exec.arg(arg);
                }
                let status = exec.spawn()?.wait()?;
                log::info!(
                    "Finished executing step {} with exit code {}",
                    idx + 1,
                    status
                );
            }
        }

        // cleanup container after execution
        log::debug!("Cleaning up after container");
        self.runtime.cleanup()?;
        Ok(0)
    }
}
