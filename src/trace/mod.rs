//! Defines the main tracer that is interfaced against for execution of a configuration.
use nix::sys::signal::Signal;
use nix::unistd;
use nix::{mount, sched};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::config::Confinement;
use crate::error::ConfineResult;
use crate::threat::ThreatReport;

// represents url used to pull down the built rootfs for the container
const UPSTREAM_ROOTFS_URL: &'static str =
    "https://github.com/ex0dus-0x/confine/releases/download/0.0.1/rootfs.tar";

/// Interface for tracing a given process and enforcing a given policy mapping.
pub struct Tracer {
    // configuration to be used during tracing
    config: Confinement,

    // path to control groups for process restriction
    cgroups: PathBuf,

    // if set, prints out each syscall dynamically
    verbose_trace: bool,

    // generated final report for potential threats and IOCs
    report: ThreatReport,
}

impl Tracer {
    /// Instantiates a new `Tracer` capable of dynamically tracing a process under a containerized
    /// environment, and enforcing policy rules.
    pub fn new(config: Confinement, verbose_trace: bool) -> ConfineResult<Self> {
        // initialize cgroup, check if supported in kernel
        let mut cgroups = PathBuf::from("/sys/fs/cgroup/pids");
        if !cgroups.exists() {
            panic!("Linux kernel does not support cgroups");
        }
        cgroups.push("confine");

        // return mostly with default arguments that gets populated
        Ok(Self {
            config,
            cgroups,
            verbose_trace,
            report: ThreatReport::default(),
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
        if let Some(_) = self.config.pull_sample()? {
            println!("=> Pulling down malware sample from upstream source...");
        }

        // execute each step, creating a `Subprocess` for those that are marked to be traced
        println!("=> Executing steps...");

        // TODO

        // unmount the procfs partition
        mount::umount("proc")?;

        // print final trace while still in cloned process
        println!("{}", self.threat_trace()?);
        Ok(0)
    }

    /// Helper that instantiates a containerized environment before the execution of the actual
    /// child process.
    fn init_container_env(&mut self) -> ConfineResult<()> {
        sched::unshare(sched::CloneFlags::CLONE_NEWNS)?;

        // keep ptrace capabilities
        unsafe {
            let _ = libc::prctl(libc::SYS_ptrace as i32);
        }

        // initialize new cgroups directory if not found
        if !self.cgroups.exists() {
            println!("=> Initialize cgroups path for restricted resources.");
            fs::create_dir_all(&self.cgroups)?;
            let mut permission = fs::metadata(&self.cgroups)?.permissions();
            permission.set_mode(511);
            fs::set_permissions(&self.cgroups, permission).ok();
        }

        // write to new cgroups directory
        fs::write(self.cgroups.join("pids.max"), b"20")?;
        fs::write(self.cgroups.join("notify_on_release"), b"1")?;
        fs::write(self.cgroups.join("cgroup.procs"), b"0")?;

        // sets the hostname for the new isolated process
        // TODO: make random string
        println!("=> Using new hostname");
        unistd::sethostname("confine")?;

        // instantiate new path to tmpdir for container creation
        println!("=> Creating ");

        // mount rootfs and go to root path
        println!("=> Mounting rootfs to root path");
        unistd::chroot("rootfs")?;
        unistd::chdir("/")?;

        // mount the proc file system
        println!("=> Mounting procfs");
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

    /// Generates a dump of the trace excluding arguments and including varying capabilities
    /// for detecting potential IOCs
    pub fn threat_trace(&mut self) -> ConfineResult<String> {
        // populate threat report with syscalls traced
        //self.report.populate(&self.manager.syscalls)?;

        // create final JSON threat report
        let json = serde_json::to_string_pretty(&self.report)?;
        Ok(json)
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.cgroups.exists() {
            fs::remove_dir(&self.cgroups).expect("Cannot delete cgroups path");
        }
    }
}
