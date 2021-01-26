use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

// Hacky macro used to create Vec<String> for type arguments
macro_rules! stringvec {
    () => (
        Vec::new()
    );
    ($($x:expr),+ $(,)?) => {
        (vec![$($x.to_string()),+])
    }
}

/// Represents a single system call definition, including its syscall number, name,
/// and a vector of argument definitions.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u64,
    pub name: &'static str,
    pub args: Vec<String>,
}

lazy_static! {
    pub static ref SYSCALL_TABLE: Vec<Syscall> = vec![
        Syscall {
            number: 0,
            name: "read",
            args: stringvec![
                "unsigned int fd",
                "char *buf",
                "size_t count"
            ]
        },
        Syscall {
            number: 1,
            name: "write",
            args: stringvec![
                "unsigned int fd",
                "char *buf",
                "size_t count"
            ]
        },
        Syscall {
            number: 2,
            name: "open",
            args: stringvec![
                "const char *filename",
                "int flags",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 3,
            name: "close",
            args: stringvec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 4,
            name: "stat",
            args: stringvec![
                "const char *filename",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 5,
            name: "fstat",
            args: stringvec![
                "unsigned int fd",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 6,
            name: "lstat",
            args: stringvec![
                "const char *filename",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 7,
            name: "poll",
            args: stringvec![
                "struct pollfd *ufds",
                "unsigned int nfds",
                "int timeout"
            ]
        },
        Syscall {
            number: 8,
            name: "lseek",
            args: stringvec![
                "unsigned int fd",
                "off_t offset",
                "unsigned int whence"
            ]
        },
        Syscall {
            number: 9,
            name: "mmap",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 10,
            name: "mprotect",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "unsigned long prot"
            ]
        },
        Syscall {
            number: 11,
            name: "munmap",
            args: stringvec![
                "unsigned long addr",
                "size_t len"
            ]
        },
        Syscall {
            number: 12,
            name: "brk",
            args: stringvec![
                "unsigned long brk"
            ]
        },
        Syscall {
            number: 13,
            name: "rt_sigaction",
            args: stringvec![
                "int",
                "const struct sigaction *",
                "struct sigaction *",
                "size_t"
            ]
        },
        Syscall {
            number: 14,
            name: "rt_sigprocmask",
            args: stringvec![
                "int how",
                "sigset_t *set",
                "sigset_t *oset",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 15,
            name: "rt_sigreturn",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 16,
            name: "ioctl",
            args: stringvec![
                "unsigned int fd",
                "unsigned int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 17,
            name: "pread64",
            args: stringvec![
                "unsigned int fd",
                "char *buf",
                "size_t count",
                "loff_t pos"
            ]
        },
        Syscall {
            number: 18,
            name: "pwrite64",
            args: stringvec![
                "unsigned int fd",
                "const char *buf",
                "size_t count",
                "loff_t pos"
            ]
        },
        Syscall {
            number: 19,
            name: "readv",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen"
            ]
        },
        Syscall {
            number: 20,
            name: "writev",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen"
            ]
        },
        Syscall {
            number: 21,
            name: "access",
            args: stringvec![
                "const char *filename",
                "int mode"
            ]
        },
        Syscall {
            number: 22,
            name: "pipe",
            args: stringvec![
                "int *fildes"
            ]
        },
        Syscall {
            number: 23,
            name: "select",
            args: stringvec![
                "int n",
                "fd_set *inp",
                "fd_set *outp",
                "fd_set *exp",
                "struct timeval *tvp"
            ]
        },
        Syscall {
            number: 24,
            name: "sched_yield",
            args: stringvec![]
        },
        Syscall {
            number: 25,
            name: "mremap",
            args: stringvec![
                "unsigned long addr",
                "unsigned long old_len",
                "unsigned long new_len",
                "unsigned long flags",
                "unsigned long new_addr"
            ]
        },
        Syscall {
            number: 26,
            name: "msync",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "int flags"
            ]
        },
        Syscall {
            number: 27,
            name: "mincore",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "unsigned char * vec"
            ]
        },
        Syscall {
            number: 28,
            name: "madvise",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "int behavior"
            ]
        },
        Syscall {
            number: 29,
            name: "shmget",
            args: stringvec![
                "key_t key",
                "size_t size",
                "int flag"
            ]
        },
        Syscall {
            number: 30,
            name: "shmat",
            args: stringvec![
                "int shmid",
                "char *shmaddr",
                "int shmflg"
            ]
        },
        Syscall {
            number: 31,
            name: "shmctl",
            args: stringvec![
                "int shmid",
                "int cmd",
                "struct shmid_ds *buf"
            ]
        },
        Syscall {
            number: 32,
            name: "dup",
            args: stringvec![
                "unsigned int fildes"
            ]
        },
        Syscall {
            number: 33,
            name: "dup2",
            args: stringvec![
                "unsigned int oldfd",
                "unsigned int newfd"
            ]
        },
        Syscall {
            number: 34,
            name: "pause",
            args: stringvec![]
        },
        Syscall {
            number: 35,
            name: "nanosleep",
            args: stringvec![
                "struct __kernel_timespec *rqtp",
                "struct __kernel_timespec *rmtp"
            ]
        },
        Syscall {
            number: 36,
            name: "getitimer",
            args: stringvec![
                "int which",
                "struct itimerval *value"
            ]
        },
        Syscall {
            number: 37,
            name: "alarm",
            args: stringvec![
                "unsigned int seconds"
            ]
        },
        Syscall {
            number: 38,
            name: "setitimer",
            args: stringvec![
                "int which",
                "struct itimerval *value",
                "struct itimerval *ovalue"
            ]
        },
        Syscall {
            number: 39,
            name: "getpid",
            args: stringvec![]
        },
        Syscall {
            number: 40,
            name: "sendfile",
            args: stringvec![
                "int out_fd",
                "int in_fd",
                "off_t *offset",
                "size_t count"
            ]
        },
        Syscall {
            number: 41,
            name: "socket",
            args: stringvec![
                "int",
                "int",
                "int"
            ]
        },
        Syscall {
            number: 42,
            name: "connect",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int"
            ]
        },
        Syscall {
            number: 43,
            name: "accept",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 44,
            name: "sendto",
            args: stringvec![
                "int",
                "void *",
                "size_t",
                "unsigned",
                "struct sockaddr *",
                "int"
            ]
        },
        Syscall {
            number: 45,
            name: "recvfrom",
            args: stringvec![
                "int",
                "void *",
                "size_t",
                "unsigned",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 46,
            name: "sendmsg",
            args: stringvec![
                "int fd",
                "struct user_msghdr *msg",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 47,
            name: "recvmsg",
            args: stringvec![
                "int fd",
                "struct user_msghdr *msg",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 48,
            name: "shutdown",
            args: stringvec![
                "int",
                "int"
            ]
        },
        Syscall {
            number: 49,
            name: "bind",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int"
            ]
        },
        Syscall {
            number: 50,
            name: "listen",
            args: stringvec![
                "int",
                "int"
            ]
        },
        Syscall {
            number: 51,
            name: "getsockname",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 52,
            name: "getpeername",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 53,
            name: "socketpair",
            args: stringvec![
                "int",
                "int",
                "int",
                "int *"
            ]
        },
        Syscall {
            number: 54,
            name: "setsockopt",
            args: stringvec![
                "int fd",
                "int level",
                "int optname",
                "char *optval",
                "int optlen"
            ]
        },
        Syscall {
            number: 55,
            name: "getsockopt",
            args: stringvec![
                "int fd",
                "int level",
                "int optname",
                "char *optval",
                "int *optlen"
            ]
        },
        Syscall {
            number: 56,
            name: "clone",
            args: stringvec![
                "unsigned long",
                "unsigned long",
                "int *",
                "int *",
                "unsigned long"
            ]
        },
        Syscall {
            number: 57,
            name: "fork",
            args: stringvec![]
        },
        Syscall {
            number: 58,
            name: "vfork",
            args: stringvec![]
        },
        Syscall {
            number: 59,
            name: "execve",
            args: stringvec![
                "const char *filename",
                "const char *const *argv",
                "const char *const *envp"
            ]
        },
        Syscall {
            number: 60,
            name: "exit",
            args: stringvec![
                "int error_code"
            ]
        },
        Syscall {
            number: 61,
            name: "wait4",
            args: stringvec![
                "pid_t pid",
                "int *stat_addr",
                "int options",
                "struct rusage *ru"
            ]
        },
        Syscall {
            number: 62,
            name: "kill",
            args: stringvec![
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 63,
            name: "uname",
            args: stringvec![
                "struct old_utsname *"
            ]
        },
        Syscall {
            number: 64,
            name: "semget",
            args: stringvec![
                "key_t key",
                "int nsems",
                "int semflg"
            ]
        },
        Syscall {
            number: 65,
            name: "semop",
            args: stringvec![
                "int semid",
                "struct sembuf *sops",
                "unsigned nsops"
            ]
        },
        Syscall {
            number: 66,
            name: "semctl",
            args: stringvec![
                "int semid",
                "int semnum",
                "int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 67,
            name: "shmdt",
            args: stringvec![
                "char *shmaddr"
            ]
        },
        Syscall {
            number: 68,
            name: "msgget",
            args: stringvec![
                "key_t key",
                "int msgflg"
            ]
        },
        Syscall {
            number: 69,
            name: "msgsnd",
            args: stringvec![
                "int msqid",
                "struct msgbuf *msgp",
                "size_t msgsz",
                "int msgflg"
            ]
        },
        Syscall {
            number: 70,
            name: "msgrcv",
            args: stringvec![
                "int msqid",
                "struct msgbuf *msgp",
                "size_t msgsz",
                "long msgtyp",
                "int msgflg"
            ]
        },
        Syscall {
            number: 71,
            name: "msgctl",
            args: stringvec![
                "int msqid",
                "int cmd",
                "struct msqid_ds *buf"
            ]
        },
        Syscall {
            number: 72,
            name: "fcntl",
            args: stringvec![
                "unsigned int fd",
                "unsigned int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 73,
            name: "flock",
            args: stringvec![
                "unsigned int fd",
                "unsigned int cmd"
            ]
        },
        Syscall {
            number: 74,
            name: "fsync",
            args: stringvec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 75,
            name: "fdatasync",
            args: stringvec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 76,
            name: "truncate",
            args: stringvec![
                "const char *path",
                "long length"
            ]
        },
        Syscall {
            number: 77,
            name: "ftruncate",
            args: stringvec![
                "unsigned int fd",
                "unsigned long length"
            ]
        },
        Syscall {
            number: 78,
            name: "getdents",
            args: stringvec![
                "unsigned int fd",
                "struct linux_dirent *dirent",
                "unsigned int count"
            ]
        },
        Syscall {
            number: 79,
            name: "getcwd",
            args: stringvec![
                "char *buf",
                "unsigned long size"
            ]
        },
        Syscall {
            number: 80,
            name: "chdir",
            args: stringvec![
                "const char *filename"
            ]
        },
        Syscall {
            number: 81,
            name: "fchdir",
            args: stringvec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 82,
            name: "rename",
            args: stringvec![
                "const char *oldname",
                "const char *newname"
            ]
        },
        Syscall {
            number: 83,
            name: "mkdir",
            args: stringvec![
                "const char *pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 84,
            name: "rmdir",
            args: stringvec![
                "const char *pathname"
            ]
        },
        Syscall {
            number: 85,
            name: "creat",
            args: stringvec![
                "const char *pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 86,
            name: "link",
            args: stringvec![
                "const char *oldname",
                "const char *newname"
            ]
        },
        Syscall {
            number: 87,
            name: "unlink",
            args: stringvec![
                "const char *pathname"
            ]
        },
        Syscall {
            number: 88,
            name: "symlink",
            args: stringvec![
                "const char *old",
                "const char *new"
            ]
        },
        Syscall {
            number: 89,
            name: "readlink",
            args: stringvec![
                "const char *path",
                "char *buf",
                "int bufsiz"
            ]
        },
        Syscall {
            number: 90,
            name: "chmod",
            args: stringvec![
                "const char *filename",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 91,
            name: "fchmod",
            args: stringvec![
                "unsigned int fd",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 92,
            name: "chown",
            args: stringvec![
                "const char *filename",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 93,
            name: "fchown",
            args: stringvec![
                "unsigned int fd",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 94,
            name: "lchown",
            args: stringvec![
                "const char *filename",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 95,
            name: "umask",
            args: stringvec![
                "int mask"
            ]
        },
        Syscall {
            number: 96,
            name: "gettimeofday",
            args: stringvec![
                "struct timeval *tv",
                "struct timezone *tz"
            ]
        },
        Syscall {
            number: 97,
            name: "getrlimit",
            args: stringvec![
                "unsigned int resource",
                "struct rlimit *rlim"
            ]
        },
        Syscall {
            number: 98,
            name: "getrusage",
            args: stringvec![
                "int who",
                "struct rusage *ru"
            ]
        },
        Syscall {
            number: 99,
            name: "sysinfo",
            args: stringvec![
                "struct sysinfo *info"
            ]
        },
        Syscall {
            number: 100,
            name: "times",
            args: stringvec![
                "struct tms *tbuf"
            ]
        },
        Syscall {
            number: 101,
            name: "ptrace",
            args: stringvec![
                "long request",
                "long pid",
                "unsigned long addr",
                "unsigned long data"
            ]
        },
        Syscall {
            number: 102,
            name: "getuid",
            args: stringvec![]
        },
        Syscall {
            number: 103,
            name: "syslog",
            args: stringvec![
                "int type",
                "char *buf",
                "int len"
            ]
        },
        Syscall {
            number: 104,
            name: "getgid",
            args: stringvec![]
        },
        Syscall {
            number: 105,
            name: "setuid",
            args: stringvec![
                "uid_t uid"
            ]
        },
        Syscall {
            number: 106,
            name: "setgid",
            args: stringvec![
                "gid_t gid"
            ]
        },
        Syscall {
            number: 107,
            name: "geteuid",
            args: stringvec![]
        },
        Syscall {
            number: 108,
            name: "getegid",
            args: stringvec![]
        },
        Syscall {
            number: 109,
            name: "setpgid",
            args: stringvec![
                "pid_t pid",
                "pid_t pgid"
            ]
        },
        Syscall {
            number: 110,
            name: "getppid",
            args: stringvec![]
        },
        Syscall {
            number: 111,
            name: "getpgrp",
            args: stringvec![]
        },
        Syscall {
            number: 112,
            name: "setsid",
            args: stringvec![]
        },
        Syscall {
            number: 113,
            name: "setreuid",
            args: stringvec![
                "uid_t ruid",
                "uid_t euid"
            ]
        },
        Syscall {
            number: 114,
            name: "setregid",
            args: stringvec![
                "gid_t rgid",
                "gid_t egid"
            ]
        },
        Syscall {
            number: 115,
            name: "getgroups",
            args: stringvec![
                "int gidsetsize",
                "gid_t *grouplist"
            ]
        },
        Syscall {
            number: 116,
            name: "setgroups",
            args: stringvec![
                "int gidsetsize",
                "gid_t *grouplist"
            ]
        },
        Syscall {
            number: 117,
            name: "setresuid",
            args: stringvec![
                "uid_t ruid",
                "uid_t euid",
                "uid_t suid"
            ]
        },
        Syscall {
            number: 118,
            name: "getresuid",
            args: stringvec![
                "uid_t *ruid",
                "uid_t *euid",
                "uid_t *suid"
            ]
        },
        Syscall {
            number: 119,
            name: "setresgid",
            args: stringvec![
                "gid_t rgid",
                "gid_t egid",
                "gid_t sgid"
            ]
        },
        Syscall {
            number: 120,
            name: "getresgid",
            args: stringvec![
                "gid_t *rgid",
                "gid_t *egid",
                "gid_t *sgid"
            ]
        },
        Syscall {
            number: 121,
            name: "getpgid",
            args: stringvec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 122,
            name: "setfsuid",
            args: stringvec![
                "uid_t uid"
            ]
        },
        Syscall {
            number: 123,
            name: "setfsgid",
            args: stringvec![
                "gid_t gid"
            ]
        },
        Syscall {
            number: 124,
            name: "getsid",
            args: stringvec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 125,
            name: "capget",
            args: stringvec![
                "cap_user_header_t header",
                "cap_user_data_t dataptr"
            ]
        },
        Syscall {
            number: 126,
            name: "capset",
            args: stringvec![
                "cap_user_header_t header",
                "const cap_user_data_t data"
            ]
        },
        Syscall {
            number: 127,
            name: "rt_sigpending",
            args: stringvec![
                "sigset_t *set",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 128,
            name: "rt_sigtimedwait",
            args: stringvec![
                "const sigset_t *uthese",
                "siginfo_t *uinfo",
                "const struct __kernel_timespec *uts",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 129,
            name: "rt_sigqueueinfo",
            args: stringvec![
                "pid_t pid",
                "int sig",
                "siginfo_t *uinfo"
            ]
        },
        Syscall {
            number: 130,
            name: "rt_sigsuspend",
            args: stringvec![
                "sigset_t *unewset",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 131,
            name: "sigaltstack",
            args: stringvec![
                "const struct sigaltstack *uss",
                "struct sigaltstack *uoss"
            ]
        },
        Syscall {
            number: 132,
            name: "utime",
            args: stringvec![
                "char *filename",
                "struct utimbuf *times"
            ]
        },
        Syscall {
            number: 133,
            name: "mknod",
            args: stringvec![
                "const char *filename",
                "umode_t mode",
                "unsigned dev"
            ]
        },
        Syscall {
            number: 134,
            name: "uselib",
            args: stringvec![
                "const char *library"
            ]
        },
        Syscall {
            number: 135,
            name: "personality",
            args: stringvec![
                "unsigned int personality"
            ]
        },
        Syscall {
            number: 136,
            name: "ustat",
            args: stringvec![
                "unsigned dev",
                "struct ustat *ubuf"
            ]
        },
        Syscall {
            number: 137,
            name: "statfs",
            args: stringvec![
                "const char * path",
                "struct statfs *buf"
            ]
        },
        Syscall {
            number: 138,
            name: "fstatfs",
            args: stringvec![
                "unsigned int fd",
                "struct statfs *buf"
            ]
        },
        Syscall {
            number: 139,
            name: "sysfs",
            args: stringvec![
                "int option",
                "unsigned long arg1",
                "unsigned long arg2"
            ]
        },
        Syscall {
            number: 140,
            name: "getpriority",
            args: stringvec![
                "int which",
                "int who"
            ]
        },
        Syscall {
            number: 141,
            name: "setpriority",
            args: stringvec![
                "int which",
                "int who",
                "int niceval"
            ]
        },
        Syscall {
            number: 142,
            name: "sched_setparam",
            args: stringvec![
                "pid_t pid",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 143,
            name: "sched_getparam",
            args: stringvec![
                "pid_t pid",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 144,
            name: "sched_setscheduler",
            args: stringvec![
                "pid_t pid",
                "int policy",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 145,
            name: "sched_getscheduler",
            args: stringvec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 146,
            name: "sched_get_priority_max",
            args: stringvec![
                "int policy"
            ]
        },
        Syscall {
            number: 147,
            name: "sched_get_priority_min",
            args: stringvec![
                "int policy"
            ]
        },
        Syscall {
            number: 148,
            name: "sched_rr_get_interval",
            args: stringvec![
                "pid_t pid",
                "struct __kernel_timespec *interval"
            ]
        },
        Syscall {
            number: 149,
            name: "mlock",
            args: stringvec![
                "unsigned long start",
                "size_t len"
            ]
        },
        Syscall {
            number: 150,
            name: "munlock",
            args: stringvec![
                "unsigned long start",
                "size_t len"
            ]
        },
        Syscall {
            number: 151,
            name: "mlockall",
            args: stringvec![
                "int flags"
            ]
        },
        Syscall {
            number: 152,
            name: "munlockall",
            args: stringvec![]
        },
        Syscall {
            number: 153,
            name: "vhangup",
            args: stringvec![]
        },
        Syscall {
            number: 154,
            name: "modify_ldt",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 155,
            name: "pivot_root",
            args: stringvec![
                "const char *new_root",
                "const char *put_old"
            ]
        },
        Syscall {
            number: 156,
            name: "_sysctl",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 157,
            name: "prctl",
            args: stringvec![
                "int option",
                "unsigned long arg2",
                "unsigned long arg3",
                "unsigned long arg4",
                "unsigned long arg5"
            ]
        },
        Syscall {
            number: 158,
            name: "arch_prctl",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 159,
            name: "adjtimex",
            args: stringvec![
                "struct __kernel_timex *txc_p"
            ]
        },
        Syscall {
            number: 160,
            name: "setrlimit",
            args: stringvec![
                "unsigned int resource",
                "struct rlimit *rlim"
            ]
        },
        Syscall {
            number: 161,
            name: "chroot",
            args: stringvec![
                "const char *filename"
            ]
        },
        Syscall {
            number: 162,
            name: "sync",
            args: stringvec![]
        },
        Syscall {
            number: 163,
            name: "acct",
            args: stringvec![
                "const char *name"
            ]
        },
        Syscall {
            number: 164,
            name: "settimeofday",
            args: stringvec![
                "struct timeval *tv",
                "struct timezone *tz"
            ]
        },
        Syscall {
            number: 165,
            name: "mount",
            args: stringvec![
                "char *dev_name",
                "char *dir_name",
                "char *type",
                "unsigned long flags",
                "void *data"
            ]
        },
        Syscall {
            number: 166,
            name: "umount2",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 167,
            name: "swapon",
            args: stringvec![
                "const char *specialfile",
                "int swap_flags"
            ]
        },
        Syscall {
            number: 168,
            name: "swapoff",
            args: stringvec![
                "const char *specialfile"
            ]
        },
        Syscall {
            number: 169,
            name: "reboot",
            args: stringvec![
                "int magic1",
                "int magic2",
                "unsigned int cmd",
                "void *arg"
            ]
        },
        Syscall {
            number: 170,
            name: "sethostname",
            args: stringvec![
                "char *name",
                "int len"
            ]
        },
        Syscall {
            number: 171,
            name: "setdomainname",
            args: stringvec![
                "char *name",
                "int len"
            ]
        },
        Syscall {
            number: 172,
            name: "iopl",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 173,
            name: "ioperm",
            args: stringvec![
                "unsigned long from",
                "unsigned long num",
                "int on"
            ]
        },
        Syscall {
            number: 174,
            name: "create_module",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 175,
            name: "init_module",
            args: stringvec![
                "void *umod",
                "unsigned long len",
                "const char *uargs"
            ]
        },
        Syscall {
            number: 176,
            name: "delete_module",
            args: stringvec![
                "const char *name_user",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 177,
            name: "get_kernel_syms",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 178,
            name: "query_module",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 179,
            name: "quotactl",
            args: stringvec![
                "unsigned int cmd",
                "const char *special",
                "qid_t id",
                "void *addr"
            ]
        },
        Syscall {
            number: 180,
            name: "nfsservctl",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 181,
            name: "getpmsg",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 182,
            name: "putpmsg",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 183,
            name: "afs_syscall",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 184,
            name: "tuxcall",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 185,
            name: "security",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 186,
            name: "gettid",
            args: stringvec![]
        },
        Syscall {
            number: 187,
            name: "readahead",
            args: stringvec![
                "int fd",
                "loff_t offset",
                "size_t count"
            ]
        },
        Syscall {
            number: 188,
            name: "setxattr",
            args: stringvec![
                "const char *path",
                "const char *name",
                "const void *value",
                "size_t size",
                "int flags"
            ]
        },
        Syscall {
            number: 189,
            name: "lsetxattr",
            args: stringvec![
                "const char *path",
                "const char *name",
                "const void *value",
                "size_t size",
                "int flags"
            ]
        },
        Syscall {
            number: 190,
            name: "fsetxattr",
            args: stringvec![
                "int fd",
                "const char *name",
                "const void *value",
                "size_t size",
                "int flags"
            ]
        },
        Syscall {
            number: 191,
            name: "getxattr",
            args: stringvec![
                "const char *path",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 192,
            name: "lgetxattr",
            args: stringvec![
                "const char *path",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 193,
            name: "fgetxattr",
            args: stringvec![
                "int fd",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 194,
            name: "listxattr",
            args: stringvec![
                "const char *path",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 195,
            name: "llistxattr",
            args: stringvec![
                "const char *path",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 196,
            name: "flistxattr",
            args: stringvec![
                "int fd",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 197,
            name: "removexattr",
            args: stringvec![
                "const char *path",
                "const char *name"
            ]
        },
        Syscall {
            number: 198,
            name: "lremovexattr",
            args: stringvec![
                "const char *path",
                "const char *name"
            ]
        },
        Syscall {
            number: 199,
            name: "fremovexattr",
            args: stringvec![
                "int fd",
                "const char *name"
            ]
        },
        Syscall {
            number: 200,
            name: "tkill",
            args: stringvec![
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 201,
            name: "time",
            args: stringvec![
                "time_t *tloc"
            ]
        },
        Syscall {
            number: 202,
            name: "futex",
            args: stringvec![
                "u32 *uaddr",
                "int op",
                "u32 val",
                "struct __kernel_timespec *utime",
                "u32 *uaddr2",
                "u32 val3"
            ]
        },
        Syscall {
            number: 203,
            name: "sched_setaffinity",
            args: stringvec![
                "pid_t pid",
                "unsigned int len",
                "unsigned long *user_mask_ptr"
            ]
        },
        Syscall {
            number: 204,
            name: "sched_getaffinity",
            args: stringvec![
                "pid_t pid",
                "unsigned int len",
                "unsigned long *user_mask_ptr"
            ]
        },
        Syscall {
            number: 205,
            name: "set_thread_area",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 206,
            name: "io_setup",
            args: stringvec![
                "unsigned nr_reqs",
                "aio_context_t *ctx"
            ]
        },
        Syscall {
            number: 207,
            name: "io_destroy",
            args: stringvec![
                "aio_context_t ctx"
            ]
        },
        Syscall {
            number: 208,
            name: "io_getevents",
            args: stringvec![
                "aio_context_t ctx_id",
                "long min_nr",
                "long nr",
                "struct io_event *events",
                "struct __kernel_timespec *timeout"
            ]
        },
        Syscall {
            number: 209,
            name: "io_submit",
            args: stringvec![
                "aio_context_t",
                "long",
                "struct iocb * *"
            ]
        },
        Syscall {
            number: 210,
            name: "io_cancel",
            args: stringvec![
                "aio_context_t ctx_id",
                "struct iocb *iocb",
                "struct io_event *result"
            ]
        },
        Syscall {
            number: 211,
            name: "get_thread_area",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 212,
            name: "lookup_dcookie",
            args: stringvec![
                "u64 cookie64",
                "char *buf",
                "size_t len"
            ]
        },
        Syscall {
            number: 213,
            name: "epoll_create",
            args: stringvec![
                "int size"
            ]
        },
        Syscall {
            number: 214,
            name: "epoll_ctl_old",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 215,
            name: "epoll_wait_old",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 216,
            name: "remap_file_pages",
            args: stringvec![
                "unsigned long start",
                "unsigned long size",
                "unsigned long prot",
                "unsigned long pgoff",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 217,
            name: "getdents64",
            args: stringvec![
                "unsigned int fd",
                "struct linux_dirent64 *dirent",
                "unsigned int count"
            ]
        },
        Syscall {
            number: 218,
            name: "set_tid_address",
            args: stringvec![
                "int *tidptr"
            ]
        },
        Syscall {
            number: 219,
            name: "restart_syscall",
            args: stringvec![]
        },
        Syscall {
            number: 220,
            name: "semtimedop",
            args: stringvec![
                "int semid",
                "struct sembuf *sops",
                "unsigned nsops",
                "const struct __kernel_timespec *timeout"
            ]
        },
        Syscall {
            number: 221,
            name: "fadvise64",
            args: stringvec![
                "int fd",
                "loff_t offset",
                "size_t len",
                "int advice"
            ]
        },
        Syscall {
            number: 222,
            name: "timer_create",
            args: stringvec![
                "clockid_t which_clock",
                "struct sigevent *timer_event_spec",
                "timer_t * created_timer_id"
            ]
        },
        Syscall {
            number: 223,
            name: "timer_settime",
            args: stringvec![
                "timer_t timer_id",
                "int flags",
                "const struct __kernel_itimerspec *new_setting",
                "struct __kernel_itimerspec *old_setting"
            ]
        },
        Syscall {
            number: 224,
            name: "timer_gettime",
            args: stringvec![
                "timer_t timer_id",
                "struct __kernel_itimerspec *setting"
            ]
        },
        Syscall {
            number: 225,
            name: "timer_getoverrun",
            args: stringvec![
                "timer_t timer_id"
            ]
        },
        Syscall {
            number: 226,
            name: "timer_delete",
            args: stringvec![
                "timer_t timer_id"
            ]
        },
        Syscall {
            number: 227,
            name: "clock_settime",
            args: stringvec![
                "clockid_t which_clock",
                "const struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 228,
            name: "clock_gettime",
            args: stringvec![
                "clockid_t which_clock",
                "struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 229,
            name: "clock_getres",
            args: stringvec![
                "clockid_t which_clock",
                "struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 230,
            name: "clock_nanosleep",
            args: stringvec![
                "clockid_t which_clock",
                "int flags",
                "const struct __kernel_timespec *rqtp",
                "struct __kernel_timespec *rmtp"
            ]
        },
        Syscall {
            number: 231,
            name: "exit_group",
            args: stringvec![
                "int error_code"
            ]
        },
        Syscall {
            number: 232,
            name: "epoll_wait",
            args: stringvec![
                "int epfd",
                "struct epoll_event *events",
                "int maxevents",
                "int timeout"
            ]
        },
        Syscall {
            number: 233,
            name: "epoll_ctl",
            args: stringvec![
                "int epfd",
                "int op",
                "int fd",
                "struct epoll_event *event"
            ]
        },
        Syscall {
            number: 234,
            name: "tgkill",
            args: stringvec![
                "pid_t tgid",
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 235,
            name: "utimes",
            args: stringvec![
                "char *filename",
                "struct timeval *utimes"
            ]
        },
        Syscall {
            number: 236,
            name: "vserver",
            args: stringvec![
                "?",
                "?",
                "?",
                "?",
                "?",
                "?"
            ]
        },
        Syscall {
            number: 237,
            name: "mbind",
            args: stringvec![
                "unsigned long start",
                "unsigned long len",
                "unsigned long mode",
                "const unsigned long *nmask",
                "unsigned long maxnode",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 238,
            name: "set_mempolicy",
            args: stringvec![
                "int mode",
                "const unsigned long *nmask",
                "unsigned long maxnode"
            ]
        },
        Syscall {
            number: 239,
            name: "get_mempolicy",
            args: stringvec![
                "int *policy",
                "unsigned long *nmask",
                "unsigned long maxnode",
                "unsigned long addr",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 240,
            name: "mq_open",
            args: stringvec![
                "const char *name",
                "int oflag",
                "umode_t mode",
                "struct mq_attr *attr"
            ]
        },
        Syscall {
            number: 241,
            name: "mq_unlink",
            args: stringvec![
                "const char *name"
            ]
        },
        Syscall {
            number: 242,
            name: "mq_timedsend",
            args: stringvec![
                "mqd_t mqdes",
                "const char *msg_ptr",
                "size_t msg_len",
                "unsigned int msg_prio",
                "const struct __kernel_timespec *abs_timeout"
            ]
        },
        Syscall {
            number: 243,
            name: "mq_timedreceive",
            args: stringvec![
                "mqd_t mqdes",
                "char *msg_ptr",
                "size_t msg_len",
                "unsigned int *msg_prio",
                "const struct __kernel_timespec *abs_timeout"
            ]
        },
        Syscall {
            number: 244,
            name: "mq_notify",
            args: stringvec![
                "mqd_t mqdes",
                "const struct sigevent *notification"
            ]
        },
        Syscall {
            number: 245,
            name: "mq_getsetattr",
            args: stringvec![
                "mqd_t mqdes",
                "const struct mq_attr *mqstat",
                "struct mq_attr *omqstat"
            ]
        },
        Syscall {
            number: 246,
            name: "kexec_load",
            args: stringvec![
                "unsigned long entry",
                "unsigned long nr_segments",
                "struct kexec_segment *segments",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 247,
            name: "waitid",
            args: stringvec![
                "int which",
                "pid_t pid",
                "struct siginfo *infop",
                "int options",
                "struct rusage *ru"
            ]
        },
        Syscall {
            number: 248,
            name: "add_key",
            args: stringvec![
                "const char *_type",
                "const char *_description",
                "const void *_payload",
                "size_t plen",
                "key_serial_t destringid"
            ]
        },
        Syscall {
            number: 249,
            name: "request_key",
            args: stringvec![
                "const char *_type",
                "const char *_description",
                "const char *_callout_info",
                "key_serial_t destringid"
            ]
        },
        Syscall {
            number: 250,
            name: "keyctl",
            args: stringvec![
                "int cmd",
                "unsigned long arg2",
                "unsigned long arg3",
                "unsigned long arg4",
                "unsigned long arg5"
            ]
        },
        Syscall {
            number: 251,
            name: "ioprio_set",
            args: stringvec![
                "int which",
                "int who",
                "int ioprio"
            ]
        },
        Syscall {
            number: 252,
            name: "ioprio_get",
            args: stringvec![
                "int which",
                "int who"
            ]
        },
        Syscall {
            number: 253,
            name: "inotify_init",
            args: stringvec![]
        },
        Syscall {
            number: 254,
            name: "inotify_add_watch",
            args: stringvec![
                "int fd",
                "const char *path",
                "u32 mask"
            ]
        },
        Syscall {
            number: 255,
            name: "inotify_rm_watch",
            args: stringvec![
                "int fd",
                "__s32 wd"
            ]
        },
        Syscall {
            number: 256,
            name: "migrate_pages",
            args: stringvec![
                "pid_t pid",
                "unsigned long maxnode",
                "const unsigned long *from",
                "const unsigned long *to"
            ]
        },
        Syscall {
            number: 257,
            name: "openat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "int flags",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 258,
            name: "mkdirat",
            args: stringvec![
                "int dfd",
                "const char * pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 259,
            name: "mknodat",
            args: stringvec![
                "int dfd",
                "const char * filename",
                "umode_t mode",
                "unsigned dev"
            ]
        },
        Syscall {
            number: 260,
            name: "fchownat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "uid_t user",
                "gid_t group",
                "int flag"
            ]
        },
        Syscall {
            number: 261,
            name: "futimesat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "struct timeval *utimes"
            ]
        },
        Syscall {
            number: 262,
            name: "newfstatat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "struct stat *statbuf",
                "int flag"
            ]
        },
        Syscall {
            number: 263,
            name: "unlinkat",
            args: stringvec![
                "int dfd",
                "const char * pathname",
                "int flag"
            ]
        },
        Syscall {
            number: 264,
            name: "renameat",
            args: stringvec![
                "int olddfd",
                "const char * oldname",
                "int newdfd",
                "const char * newname"
            ]
        },
        Syscall {
            number: 265,
            name: "linkat",
            args: stringvec![
                "int olddfd",
                "const char *oldname",
                "int newdfd",
                "const char *newname",
                "int flags"
            ]
        },
        Syscall {
            number: 266,
            name: "symlinkat",
            args: stringvec![
                "const char * oldname",
                "int newdfd",
                "const char * newname"
            ]
        },
        Syscall {
            number: 267,
            name: "readlinkat",
            args: stringvec![
                "int dfd",
                "const char *path",
                "char *buf",
                "int bufsiz"
            ]
        },
        Syscall {
            number: 268,
            name: "fchmodat",
            args: stringvec![
                "int dfd",
                "const char * filename",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 269,
            name: "faccessat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "int mode"
            ]
        },
        Syscall {
            number: 270,
            name: "pselect6",
            args: stringvec![
                "int",
                "fd_set *",
                "fd_set *",
                "fd_set *",
                "struct __kernel_timespec *",
                "void *"
            ]
        },
        Syscall {
            number: 271,
            name: "ppoll",
            args: stringvec![
                "struct pollfd *",
                "unsigned int",
                "struct __kernel_timespec *",
                "const sigset_t *",
                "size_t"
            ]
        },
        Syscall {
            number: 272,
            name: "unshare",
            args: stringvec![
                "unsigned long unshare_flags"
            ]
        },
        Syscall {
            number: 273,
            name: "set_robust_list",
            args: stringvec![
                "struct robust_list_head *head",
                "size_t len"
            ]
        },
        Syscall {
            number: 274,
            name: "get_robust_list",
            args: stringvec![
                "int pid",
                "struct robust_list_head * *head_ptr",
                "size_t *len_ptr"
            ]
        },
        Syscall {
            number: 275,
            name: "splice",
            args: stringvec![
                "int fd_in",
                "loff_t *off_in",
                "int fd_out",
                "loff_t *off_out",
                "size_t len",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 276,
            name: "tee",
            args: stringvec![
                "int fdin",
                "int fdout",
                "size_t len",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 277,
            name: "sync_file_range",
            args: stringvec![
                "int fd",
                "loff_t offset",
                "loff_t nbytes",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 278,
            name: "vmsplice",
            args: stringvec![
                "int fd",
                "const struct iovec *iov",
                "unsigned long nr_segs",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 279,
            name: "move_pages",
            args: stringvec![
                "pid_t pid",
                "unsigned long nr_pages",
                "const void * *pages",
                "const int *nodes",
                "int *status",
                "int flags"
            ]
        },
        Syscall {
            number: 280,
            name: "utimensat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "struct __kernel_timespec *utimes",
                "int flags"
            ]
        },
        Syscall {
            number: 281,
            name: "epoll_pwait",
            args: stringvec![
                "int epfd",
                "struct epoll_event *events",
                "int maxevents",
                "int timeout",
                "const sigset_t *sigmask",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 282,
            name: "signalfd",
            args: stringvec![
                "int ufd",
                "sigset_t *user_mask",
                "size_t sizemask"
            ]
        },
        Syscall {
            number: 283,
            name: "timerfd_create",
            args: stringvec![
                "int clockid",
                "int flags"
            ]
        },
        Syscall {
            number: 284,
            name: "eventfd",
            args: stringvec![
                "unsigned int count"
            ]
        },
        Syscall {
            number: 285,
            name: "fallocate",
            args: stringvec![
                "int fd",
                "int mode",
                "loff_t offset",
                "loff_t len"
            ]
        },
        Syscall {
            number: 286,
            name: "timerfd_settime",
            args: stringvec![
                "int ufd",
                "int flags",
                "const struct __kernel_itimerspec *utmr",
                "struct __kernel_itimerspec *otmr"
            ]
        },
        Syscall {
            number: 287,
            name: "timerfd_gettime",
            args: stringvec![
                "int ufd",
                "struct __kernel_itimerspec *otmr"
            ]
        },
        Syscall {
            number: 288,
            name: "accept4",
            args: stringvec![
                "int",
                "struct sockaddr *",
                "int *",
                "int"
            ]
        },
        Syscall {
            number: 289,
            name: "signalfd4",
            args: stringvec![
                "int ufd",
                "sigset_t *user_mask",
                "size_t sizemask",
                "int flags"
            ]
        },
        Syscall {
            number: 290,
            name: "eventfd2",
            args: stringvec![
                "unsigned int count",
                "int flags"
            ]
        },
        Syscall {
            number: 291,
            name: "epoll_create1",
            args: stringvec![
                "int flags"
            ]
        },
        Syscall {
            number: 292,
            name: "dup3",
            args: stringvec![
                "unsigned int oldfd",
                "unsigned int newfd",
                "int flags"
            ]
        },
        Syscall {
            number: 293,
            name: "pipe2",
            args: stringvec![
                "int *fildes",
                "int flags"
            ]
        },
        Syscall {
            number: 294,
            name: "inotify_init1",
            args: stringvec![
                "int flags"
            ]
        },
        Syscall {
            number: 295,
            name: "preadv",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen",
                "unsigned long pos_l",
                "unsigned long pos_h"
            ]
        },
        Syscall {
            number: 296,
            name: "pwritev",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen",
                "unsigned long pos_l",
                "unsigned long pos_h"
            ]
        },
        Syscall {
            number: 297,
            name: "rt_tgsigqueueinfo",
            args: stringvec![
                "pid_t tgid",
                "pid_t pid",
                "int sig",
                "siginfo_t *uinfo"
            ]
        },
        Syscall {
            number: 298,
            name: "perf_event_open",
            args: stringvec![
                "struct perf_event_attr *attr_uptr",
                "pid_t pid",
                "int cpu",
                "int group_fd",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 299,
            name: "recvmmsg",
            args: stringvec![
                "int fd",
                "struct mmsghdr *msg",
                "unsigned int vlen",
                "unsigned flags",
                "struct __kernel_timespec *timeout"
            ]
        },
        Syscall {
            number: 300,
            name: "fanotify_init",
            args: stringvec![
                "unsigned int flags",
                "unsigned int event_f_flags"
            ]
        },
        Syscall {
            number: 301,
            name: "fanotify_mark",
            args: stringvec![
                "int fanotify_fd",
                "unsigned int flags",
                "u64 mask",
                "int fd",
                "const char *pathname"
            ]
        },
        Syscall {
            number: 302,
            name: "prlimit64",
            args: stringvec![
                "pid_t pid",
                "unsigned int resource",
                "const struct rlimit64 *new_rlim",
                "struct rlimit64 *old_rlim"
            ]
        },
        Syscall {
            number: 303,
            name: "name_to_handle_at",
            args: stringvec![
                "int dfd",
                "const char *name",
                "struct file_handle *handle",
                "int *mnt_id",
                "int flag"
            ]
        },
        Syscall {
            number: 304,
            name: "open_by_handle_at",
            args: stringvec![
                "int mountdirfd",
                "struct file_handle *handle",
                "int flags"
            ]
        },
        Syscall {
            number: 305,
            name: "clock_adjtime",
            args: stringvec![
                "clockid_t which_clock",
                "struct __kernel_timex *tx"
            ]
        },
        Syscall {
            number: 306,
            name: "syncfs",
            args: stringvec![
                "int fd"
            ]
        },
        Syscall {
            number: 307,
            name: "sendmmsg",
            args: stringvec![
                "int fd",
                "struct mmsghdr *msg",
                "unsigned int vlen",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 308,
            name: "setns",
            args: stringvec![
                "int fd",
                "int nstype"
            ]
        },
        Syscall {
            number: 309,
            name: "getcpu",
            args: stringvec![
                "unsigned *cpu",
                "unsigned *node",
                "struct getcpu_cache *cache"
            ]
        },
        Syscall {
            number: 310,
            name: "process_vm_readv",
            args: stringvec![
                "pid_t pid",
                "const struct iovec *lvec",
                "unsigned long liovcnt",
                "const struct iovec *rvec",
                "unsigned long riovcnt",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 311,
            name: "process_vm_writev",
            args: stringvec![
                "pid_t pid",
                "const struct iovec *lvec",
                "unsigned long liovcnt",
                "const struct iovec *rvec",
                "unsigned long riovcnt",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 312,
            name: "kcmp",
            args: stringvec![
                "pid_t pid1",
                "pid_t pid2",
                "int type",
                "unsigned long idx1",
                "unsigned long idx2"
            ]
        },
        Syscall {
            number: 313,
            name: "finit_module",
            args: stringvec![
                "int fd",
                "const char *uargs",
                "int flags"
            ]
        },
        Syscall {
            number: 314,
            name: "sched_setattr",
            args: stringvec![
                "pid_t pid",
                "struct sched_attr *attr",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 315,
            name: "sched_getattr",
            args: stringvec![
                "pid_t pid",
                "struct sched_attr *attr",
                "unsigned int size",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 316,
            name: "renameat2",
            args: stringvec![
                "int olddfd",
                "const char *oldname",
                "int newdfd",
                "const char *newname",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 317,
            name: "seccomp",
            args: stringvec![
                "unsigned int op",
                "unsigned int flags",
                "void *uargs"
            ]
        },
        Syscall {
            number: 318,
            name: "getrandom",
            args: stringvec![
                "char *buf",
                "size_t count",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 319,
            name: "memfd_create",
            args: stringvec![
                "const char *uname_ptr",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 320,
            name: "kexec_file_load",
            args: stringvec![
                "int kernel_fd",
                "int initrd_fd",
                "unsigned long cmdline_len",
                "const char *cmdline_ptr",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 321,
            name: "bpf",
            args: stringvec![
                "int cmd",
                "union bpf_attr *attr",
                "unsigned int size"
            ]
        },
        Syscall {
            number: 322,
            name: "execveat",
            args: stringvec![
                "int dfd",
                "const char *filename",
                "const char *const *argv",
                "const char *const *envp",
                "int flags"
            ]
        },
        Syscall {
            number: 323,
            name: "userfaultfd",
            args: stringvec![
                "int flags"
            ]
        },
        Syscall {
            number: 324,
            name: "membarrier",
            args: stringvec![
                "int cmd",
                "int flags"
            ]
        },
        Syscall {
            number: 325,
            name: "mlock2",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "int flags"
            ]
        },
        Syscall {
            number: 326,
            name: "copy_file_range",
            args: stringvec![
                "int fd_in",
                "loff_t *off_in",
                "int fd_out",
                "loff_t *off_out",
                "size_t len",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 327,
            name: "preadv2",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen",
                "unsigned long pos_l",
                "unsigned long pos_h",
                "rwf_t flags"
            ]
        },
        Syscall {
            number: 328,
            name: "pwritev2",
            args: stringvec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen",
                "unsigned long pos_l",
                "unsigned long pos_h",
                "rwf_t flags"
            ]
        },
        Syscall {
            number: 329,
            name: "pkey_mprotect",
            args: stringvec![
                "unsigned long start",
                "size_t len",
                "unsigned long prot",
                "int pkey"
            ]
        },
        Syscall {
            number: 330,
            name: "pkey_alloc",
            args: stringvec![
                "unsigned long flags",
                "unsigned long init_val"
            ]
        },
        Syscall {
            number: 331,
            name: "pkey_free",
            args: stringvec![
                "int pkey"
            ]
        },
        Syscall {
            number: 332,
            name: "statx",
            args: stringvec![
                "int dfd",
                "const char *path",
                "unsigned flags",
                "unsigned mask",
                "struct statx *buffer"
            ]
        },
    ];
}
