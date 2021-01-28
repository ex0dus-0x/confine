//! Implements container runtime that is initialized before the execution of the debuge.
use nix::{mount, sched, unistd};

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{env, fs};

use flate2::read::GzDecoder;
use tar::Archive;

use crate::error::ConfineResult;

// represents url used to pull down the built rootfs for the container
const UPSTREAM_ROOTFS_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/alpine-minirootfs-3.13.0-x86_64.tar.gz";

/// Encapsulates implementation and resource deallocation of a container runtime.
pub struct Container {
    // hostname used for new container mount, random or specified
    hostname: String,

    // temp dir used to store rootfs mountpath
    mountpath: PathBuf,

    // path to cgroups for resource restrictions
    cgroups: PathBuf,
}

impl Container {
    /// Initializes new `Container` with initial state of where resources are located
    /// in the host filesystem.
    pub fn init(rootfs: Option<&str>, _hostname: Option<&str>) -> ConfineResult<Self> {
        // initialize cgroup, check if supported in kernel
        let mut cgroups = PathBuf::from("/sys/fs/cgroup/pids");
        if !cgroups.exists() {
            log::error!("Linux kernel does not support cgroups.");
            std::process::exit(1);
        }
        cgroups.push("confine");

        log::trace!("Cgroups path: {:?}", cgroups);

        // check if optional hostname specified, otherwise generate random
        let hostname: String = match _hostname {
            Some(hn) => hn.to_string(),
            None => Container::gen_hostname(),
        };

        log::trace!("Hostname: {}", hostname);

        // if mountpath isn't specified, create temp one with new rootfs immediately
        let mountpath: PathBuf = match rootfs {
            Some(path) => {
                let mut abspath = PathBuf::new();
                abspath.push(env::current_dir()?);
                abspath.push(path);
                abspath
            }
            None => {
                let mut path = env::temp_dir();
                path.push(format!("tmp_{}", hostname));
                if let Err(e) = Container::init_new_rootfs(&path) {
                    return Err(e);
                }
                path
            }
        };

        log::trace!("Mountpath: {:?}", mountpath);

        Ok(Self {
            hostname,
            mountpath,
            cgroups,
        })
    }

    /// Helper that creates a randomly generated hostname with the `names` crate.
    #[inline]
    fn gen_hostname() -> String {
        use names::{Generator, Name};
        let mut generator = Generator::with_naming(Name::Numbered);
        generator.next().unwrap()
    }

    /// Create a new tempdir, and untar the rootfs into the tempdir. Should be called before
    /// actually starting the container to initialize the mountpath state before entering the
    /// restricted cloned process.
    #[inline]
    fn init_new_rootfs(rootfs: &PathBuf) -> ConfineResult<()> {
        log::debug!("Creating tempdir for mountpath");
        fs::create_dir(rootfs)?;
        env::set_current_dir(rootfs)?;

        log::info!("Downloading alpine rootfs from upstream...");
        let resp = ureq::get(UPSTREAM_ROOTFS_URL).call()?;

        let len = resp
            .header("Content-Length")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap();
        log::trace!("Reading {} bytes of content from response", len);

        let mut rootfs_contents: Vec<u8> = Vec::with_capacity(len);
        resp.into_reader().read_to_end(&mut rootfs_contents)?;

        log::debug!("Unarchiving the tarball for the rootfs");
        let tar = GzDecoder::new(&rootfs_contents[..]);
        let mut archive = Archive::new(tar);
        archive.unpack(".")?;
        Ok(())
    }

    /// Start the container runtime, creating the necessary cgroups configuration, mounts, and
    /// unsharing namespaces.
    pub fn start(&mut self) -> ConfineResult<()> {
        log::info!("Unsharing namespaces...");
        sched::unshare(sched::CloneFlags::CLONE_NEWNS)?;

        // keep ptrace capabilities
        log::info!("Preserving capabilities...");
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

        log::debug!("Writing to cgroups directory");
        fs::write(self.cgroups.join("pids.max"), b"20")?;
        fs::write(self.cgroups.join("notify_on_release"), b"1")?;
        fs::write(self.cgroups.join("cgroup.procs"), b"0")?;

        log::info!("Setting new hostname `{}`...", self.hostname);
        unistd::sethostname(&self.hostname)?;

        log::info!("Mounting rootfs to root path...");
        unistd::chroot(&self.mountpath)?;

        log::debug!("Changing to `/` dir in rootfs");
        unistd::chdir("/")?;

        // mount the procfs in container to hide away host processes
        log::info!("Mounting procfs...");
        mount::mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            mount::MsFlags::empty(),
            None::<&str>,
        )?;

        // mount tmpfs
        log::info!("Mounting tmpfs...");
        mount::mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            mount::MsFlags::empty(),
            None::<&str>,
        )?;
        Ok(())
    }


    /// Container resource cleanup routine, replaces `Drop` implementation.
    pub fn cleanup(&self) -> ConfineResult<()> {
        log::trace!("Unmounting procfs in rootfs");
        mount::umount("/proc")?;

        log::trace!("Unmounting procfs in rootfs");
        mount::umount("/dev")?;

        // get rid of cgroups limits
        if self.cgroups.exists() {
            log::trace!("Removing cgroups");
            fs::remove_dir(&self.cgroups)?;
        }
        Ok(())
    }
}
