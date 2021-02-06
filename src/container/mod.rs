//! Implements container runtime that is initialized before the execution of the debuge.
use nix::{sched, unistd};
use nix::sys::stat;
use nix::mount::{self, MsFlags};

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{env, fs};

use flate2::read::GzDecoder;
use tar::Archive;
use walkdir::WalkDir;

use crate::error::ConfineResult;
use crate::policy::Policy;

// TODO: small image management module

const ALPINE_BASE_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/alpine-minirootfs-3.13.0-x86_64.tar.gz";

/*
const UBUNTU_BASE_URL: &str =
    "http://cdimage.ubuntu.com/ubuntu-base/releases/14.04/release/ubuntu-base-14.04-core-amd64.tar.gz";
*/

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

    /// Creates initial state of the environment that is necessary for container provisioning,
    /// includes rootfs mount and workspace containing resources, and other configs.
    pub fn init(rootfs: Option<&str>, policy: &Policy, _hostname: Option<&str>) -> ConfineResult<Self> {
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

        log::debug!("Hostname: {}", hostname);

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

        log::debug!("Mountpath: {:?}", mountpath);

        // with new mountpath, copy over contents of workspace over to /home directory
        let new_ws: PathBuf = mountpath.join("home");

        for entry in WalkDir::new(&policy.workspace).into_iter().filter_map(|e| e.ok()) {
            let copy_path = entry.path();

            // skip directories and Confinements
            if copy_path.is_dir() || copy_path.ends_with("Confinement") {
                continue;
            }

            let new_path: PathBuf = new_ws.join(copy_path.file_name().unwrap());
            log::trace!("Copying {:?} to {:?}", entry, new_path);
            fs::copy(&copy_path, &new_path)?;
        }

        // with new mountpath, pull sample if `url` is set for policy
        if policy.pull_sample(&mountpath)?.is_some() {
            log::info!("Pulling down malware sample from upstream source...");
        }

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

        log::info!("Downloading base image from upstream...");
        let resp = ureq::get(ALPINE_BASE_URL).call()?;

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
        log::info!("Preserving necessary capabilities...");
        unsafe {
            let _ = libc::prctl(libc::SYS_ptrace as i32);
        }

        log::info!("Initialize cgroups for restricted resources...");
        self.init_cgroups()?;

        log::info!("Mounting base image...");
        self.init_mountpath()?;

        log::info!("Setting new hostname `{}`...", self.hostname);
        unistd::sethostname(&self.hostname)?;
        Ok(())
    }

    /// Configures a new cgroups for the isolated process.
    fn init_cgroups(&self) -> ConfineResult<()> {
        // initialize new cgroups directory if not found
        if !self.cgroups.exists() {
            log::trace!("Creating cgroups directory");
            fs::create_dir_all(&self.cgroups)?;
            let mut permission = fs::metadata(&self.cgroups)?.permissions();
            permission.set_mode(511);
            fs::set_permissions(&self.cgroups, permission).ok();
        }

        log::trace!("Writing to cgroups directory");
        fs::write(self.cgroups.join("pids.max"), b"20")?;
        fs::write(self.cgroups.join("notify_on_release"), b"1")?;
        fs::write(self.cgroups.join("cgroup.procs"), b"0")?;
        Ok(())
    }

    /// Configures necessary filesystem mount sfor the isolated process.
    fn init_mountpath(&self) -> ConfineResult<()> {
        // new_root and put_old must not be on the same filesystem as the current root
        let rootfs: Option<&str> = self.mountpath.to_str();
        mount::mount(
            rootfs,
            rootfs.unwrap(),
            Some("bind"),
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;

        log::trace!("Creating path from the previous rootfs");
        let put_old: PathBuf = self.mountpath.join(".pivot_root");

        // remove if exists, and recreate
        if put_old.exists() {
            fs::remove_dir_all(&put_old)?;
        }
        unistd::mkdir(
            &put_old,
            stat::Mode::S_IRWXU | stat::Mode::S_IRWXG | stat::Mode::S_IRWXO
        )?;

        log::trace!("Mounting with pivot_root");
        unistd::pivot_root(&self.mountpath, &put_old)?;

        log::trace!("Changing to `/home` dir");
        unistd::chdir("/home")?;

        log::trace!("Unmounting and deleting old rootfs");
        mount::umount2("/.pivot_root", mount::MntFlags::MNT_DETACH)?;
        fs::remove_dir_all("/.pivot_root")?;

        // mount the procfs in container to hide away host processes
        log::trace!("Mounting procfs");
        mount::mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::empty(),
            None::<&str>,
        )?;

        // mount tmpfs
        log::trace!("Mounting tmpfs");
        mount::mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            MsFlags::empty(),
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

        if self.cgroups.exists() {
            log::trace!("Removing cgroups");
            fs::remove_dir(&self.cgroups)?;
        }
        Ok(())
    }
}
