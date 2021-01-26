//! Defines the main tracer that is interfaced against for execution of a configuration.
use nix::sys::signal::Signal;
use nix::{mount, sched};

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
        // initialize child process stack
        let stack = &mut [0; 1024 * 1024];

        // create function callback for cloning, with error-handling
        let callback = Box::new(|| {
            if let Err(e) = self.exec_container_trace() {
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
        sched::clone(callback, stack, clone_flags, Some(Signal::SIGCHLD as i32))?;
        Ok(())
    }

    /// Executes a dynamic `ptrace`-based trace upon the given application specified. Will first
    /// instantiate a containerized environment with unshared namespaces and a seperately mounted
    /// filesystem, and then spawn the tracee.
    fn exec_container_trace(&mut self) -> ConfineResult<isize> {
        // create the container environment to execute processes under
        self.runtime.start()?;

        // pull malware sample to container if `url` is set for config
        if self.config.pull_sample()?.is_some() {
            log::info!("Pulling down malware sample from upstream source...");
        }

        // execute each step, creating a `Subprocess` for those that are marked to be traced
        log::info!("Executing steps...");
        for (idx, step) in self.config.execution.iter().enumerate() {
            let cmd: Vec<String> = step.command.clone();
            if let Some(true) = step.trace {
                log::info!("Running traced step {}: `{}`...", idx + 1, step.name);
                let mut sb: Subprocess = Subprocess::new(cmd, self.config.policy.clone())?;

                log::trace!("ptracing the child");
                sb.trace()?;

                // once done, output capabilities trace
                println!("{}", sb.threat_trace()?);
            } else {
                log::info!("Running un-traced step {}: `{}`...", idx + 1, step.name);
                let mut exec: Command = Command::new(&cmd[0]);
                for arg in cmd.iter().skip(1) {
                    exec.arg(arg);
                }
                let status = exec.spawn()?.wait()?;
                log::info!("Finished executing step {} with exit code {}", idx + 1, status);
            }
        }

        // unmount the procfs partition
        log::trace!("Unmounting procfs in rootfs");
        mount::umount("proc")?;
        Ok(0)
    }
}
