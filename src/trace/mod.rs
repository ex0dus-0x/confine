//! Defines the main debugr that is interfaced against for execution of a policyuration.
use nix::mount::{self, MsFlags};
use nix::sched;
use nix::sys::signal::Signal;
use nix::sys::wait;

use std::process::Command;

mod subprocess;

use crate::container::Container;
use crate::error::ConfineResult;
use crate::policy::Policy;
use crate::trace::subprocess::Subprocess;

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // policy to be used during tracing
    policy: Policy,

    // container interface
    runtime: Container,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(policy: Policy) -> ConfineResult<Self> {
        let runtime = Container::init(&policy)?;
        Ok(Self { policy, runtime })
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
            if let Err(e) = self.trace() {
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

        log::trace!("Cloning new process with unshared namespaces");
        let child = sched::clone(callback, stack, clone_flags, Some(Signal::SIGCHLD as i32))?;

        log::debug!("Waiting for process to complete");
        wait::waitpid(child, None)?;
        Ok(())
    }

    /// Dynamically traces the application specified in the container environment.
    fn trace(&mut self) -> ConfineResult<isize> {
        // go to workspace
        std::env::set_current_dir(&self.policy.workspace)?;

        // execute setup steps before going into container
        if let Some(setup) = self.policy.get_setup() {
            log::info!("Setting up the environment...");
            for (idx, step) in setup.iter().enumerate() {
                let cmd: Vec<String> = step.command.clone();
                let mut exec: Command = Command::new(&cmd[0]);
                for arg in cmd.iter().skip(1) {
                    exec.arg(arg);
                }

                log::debug!("Running setup step {}", idx + 1);
                let status = exec.spawn()?.wait()?;

                // TODO: handle stopping and outputting error
                if !status.success() {}
            }
        }

        // create the container environment to execute processes under
        log::trace!("Starting container");
        self.runtime.start()?;

        // execute each step, creating a `Subprocess` for those that are marked to be debugged
        log::info!("Executing steps...");
        for (idx, step) in self.policy.get_exec().iter().enumerate() {
            let cmd: Vec<String> = step.command.clone();
            if let Some(true) = step.trace {
                log::info!("Running traced step {}: `{}`...", idx + 1, step.name);
                let mut sb = Subprocess::new(cmd, self.policy.get_filter().clone())?;

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
