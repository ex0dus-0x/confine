//! Implements container runtime that is initialized before the execution of the tracee.
use nix::{sched, unistd, mount};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::error::ConfineResult;

// represents url used to pull down the built rootfs for the container
const UPSTREAM_ROOTFS_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/alpine-minirootfs-3.13.0-x86_64.tar.gz";


/// Encapsulates implementation and resource deallocation of a container runtime.
pub struct Container {
    // hostname used for new container mount, random or specified
    hostname: String,

    // temp dir used to store rootfs mountpoint
    mountpath: PathBuf,

    // path to cgroups for resource restrictions
    cgroups: PathBuf,
}

impl Container {
    /// Initializes new `Container` with initial state of where resources are located 
    /// in the host filesystem.
    pub fn new(_hostname: Option<&str>) -> Self {
        // initialize cgroup, check if supported in kernel
        let mut cgroups = PathBuf::from("/sys/fs/cgroup/pids");
        if !cgroups.exists() {
            log::error!("Linux kernel does not support cgroups.");
            std::process::exit(1);
        }
        cgroups.push("confine");

        // check if optional hostname specified, otherwise generate random
        let hostname: String = match _hostname {
            Some(hn) => hn.to_string(),
            None => Container::gen_hostname(),
        };

        // defines path to tempdir
        let mut mountpath: PathBuf = std::env::temp_dir();
        mountpath.push("tmp_confine");
 
        Self {
            hostname,
            mountpath,
            cgroups,
        }
    }

    /// Helper that creates a randomly generated hostname.
    #[inline]
    fn gen_hostname() -> String {
        todo!()
    }


    pub fn start(&mut self) -> ConfineResult<()> {
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

        // mount the procfs in container to hide away host processes
        log::info!("Mounting procfs");
        mount::mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            mount::MsFlags::empty(),
            None::<&str>,
        )?;

        // mount tmpfs 
        mount::mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            mount::MsFlags::empty(),
            None::<&str>,
        )?;

       Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        if self.cgroups.exists() {
            log::trace!("Removing cgroups");
            fs::remove_dir(&self.cgroups).expect("Cannot delete cgroups path");
        }
    }
}
