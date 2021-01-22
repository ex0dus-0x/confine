//! Defines the main tracer that is interfaced against for execution of a configuration.
use nix::sys::signal::Signal;
use nix::unistd;
use nix::{mount, sched};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

mod subprocess;

use crate::config::Confinement;
use crate::error::ConfineResult;
use crate::trace::subprocess::Subprocess;

// represents url used to pull down the built rootfs for the container
const UPSTREAM_ROOTFS_URL: &str =
    "https://github.com/ex0dus-0x/confine/releases/download/0.0.1/rootfs.tar";

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // configuration to be used during tracing
    config: Confinement,

    // TODO: container interface

    // path to control groups for process restriction
    cgroups: PathBuf,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(config: Confinement) -> ConfineResult<Self> {
        // initialize cgroup, check if supported in kernel
        let mut cgroups = PathBuf::from("/sys/fs/cgroup/pids");
        if !cgroups.exists() {
            panic!("Linux kernel does not support cgroups");
        }
        cgroups.push("confine");

        // return mostly with default arguments that gets populated
        Ok(Self { config, cgroups })
    }

    /// Encapsulates container runtime creation and process tracing execution under a callback that
    /// is cloned to run.
    pub fn run(&mut self) -> ConfineResult<()> {
        // initialize child process stack
        let stack = &mut [0; 1024 * 1024];

        // create function callback for cloning, with error-handling
        let callback = Box::new(|| {
            if let Err(e) = self.exec_container_trace() {
                log::error!("Cannot create container: {}", e);
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
        self.init_container_env()?;

        // pull malware sample to container if `url` is set for config
        if self.config.pull_sample()?.is_some() {
            log::info!("Pulling down malware sample from upstream source...");
        }

        // execute each step, creating a `Subprocess` for those that are marked to be traced
        log::info!("Executing steps...");
        for (idx, step) in self.config.execution.iter().enumerate() {
            let cmd: Vec<String> = step.command.clone();
            if let Some(true) = step.trace {
                log::info!("Running traced step {}: `{}`", idx, step.name);
                let mut sb: Subprocess = Subprocess::new(cmd, self.config.policy.clone());
                sb.trace()?;

                // once done, output capabilities trace
                println!("{}", sb.threat_trace()?);
            } else {
                log::info!("Running step {}: `{}`", idx, step.name);
            }
        }

        // unmount the procfs partition
        log::trace!("Unmounting procfs in rootfs");
        mount::umount("proc")?;
        Ok(0)
    }

    /// Helper that instantiates a containerized environment before the execution of the actual
    /// child process.
    fn init_container_env(&mut self) -> ConfineResult<()> {
        log::info!("Unsharing namespaces...");
        sched::unshare(sched::CloneFlags::CLONE_NEWNS)?;

        // keep ptrace capabilities
        log::info!("Tweaking capabilities...");
        unsafe {
            let _ = libc::prctl(libc::SYS_ptrace as i32);
        }

        // initialize new cgroups directory if not found
        if !self.cgroups.exists() {
            log::info!("Initialize cgroups for restricted resources...");
            fs::create_dir_all(&self.cgroups)?;
            let mut permission = fs::metadata(&self.cgroups)?.permissions();
            permission.set_mode(511);
            fs::set_permissions(&self.cgroups, permission).ok();
        }

        // write to new cgroups directory
        log::trace!("Writing to cgroups directory");
        fs::write(self.cgroups.join("pids.max"), b"20")?;
        fs::write(self.cgroups.join("notify_on_release"), b"1")?;
        fs::write(self.cgroups.join("cgroup.procs"), b"0")?;

        // sets the hostname for the new isolated process
        // TODO: make random string
        log::info!("Generating new hostname for hostname...");
        unistd::sethostname("confine")?;

        // instantiate new path to tmpdir for container creation

        // mount rootfs and go to root path
        log::info!("Mounting rootfs to root path...");
        unistd::chroot("rootfs")?;

        log::trace!("Chrooting to / in rootfs");
        unistd::chdir("/")?;

        // mount the proc file system
        log::info!("Mounting procfs");
        const NONE: Option<&'static [u8]> = None;
        mount::mount(
            Some("proc"),
            "proc",
            Some("proc"),
            mount::MsFlags::empty(),
            NONE,
        )?;
        Ok(())
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.cgroups.exists() {
            log::trace!("Removing cgroups");
            fs::remove_dir(&self.cgroups).expect("Cannot delete cgroups path");
        }
    }
}
