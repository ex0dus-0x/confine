use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

/// Represents a single system call definition, including its syscall number, name,
/// and a vector of argument definitions.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u64,
    pub name: &'static str,
    pub args: Vec<&'static str>,
}

lazy_static! {
    pub static ref SYSCALL_TABLE: Vec<Syscall> = vec![
        Syscall {
            number: 0,
            name: "read",
            args: vec![
                "unsigned int fd",
                "char *buf",
                "size_t count"
            ]
        },
        Syscall {
            number: 1,
            name: "write",
            args: vec![
                "unsigned int fd",
                "char *buf",
                "size_t count"
            ]
        },
        Syscall {
            number: 2,
            name: "open",
            args: vec![
                "const char *filename",
                "int flags",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 3,
            name: "close",
            args: vec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 4,
            name: "stat",
            args: vec![
                "const char *filename",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 5,
            name: "fstat",
            args: vec![
                "unsigned int fd",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 6,
            name: "lstat",
            args: vec![
                "const char *filename",
                "struct __old_kernel_stat *statbuf"
            ]
        },
        Syscall {
            number: 7,
            name: "poll",
            args: vec![
                "struct pollfd *ufds",
                "unsigned int nfds",
                "int timeout"
            ]
        },
        Syscall {
            number: 8,
            name: "lseek",
            args: vec![
                "unsigned int fd",
                "off_t offset",
                "unsigned int whence"
            ]
        },
        Syscall {
            number: 9,
            name: "mmap",
            args: vec![
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
            args: vec![
                "unsigned long start",
                "size_t len",
                "unsigned long prot"
            ]
        },
        Syscall {
            number: 11,
            name: "munmap",
            args: vec![
                "unsigned long addr",
                "size_t len"
            ]
        },
        Syscall {
            number: 12,
            name: "brk",
            args: vec![
                "unsigned long brk"
            ]
        },
        Syscall {
            number: 13,
            name: "rt_sigaction",
            args: vec![
                "int",
                "const struct sigaction *",
                "struct sigaction *",
                "size_t"
            ]
        },
        Syscall {
            number: 14,
            name: "rt_sigprocmask",
            args: vec![
                "int how",
                "sigset_t *set",
                "sigset_t *oset",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 15,
            name: "rt_sigreturn",
            args: vec![
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
            args: vec![
                "unsigned int fd",
                "unsigned int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 17,
            name: "pread64",
            args: vec![
                "unsigned int fd",
                "char *buf",
                "size_t count",
                "loff_t pos"
            ]
        },
        Syscall {
            number: 18,
            name: "pwrite64",
            args: vec![
                "unsigned int fd",
                "const char *buf",
                "size_t count",
                "loff_t pos"
            ]
        },
        Syscall {
            number: 19,
            name: "readv",
            args: vec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen"
            ]
        },
        Syscall {
            number: 20,
            name: "writev",
            args: vec![
                "unsigned long fd",
                "const struct iovec *vec",
                "unsigned long vlen"
            ]
        },
        Syscall {
            number: 21,
            name: "access",
            args: vec![
                "const char *filename",
                "int mode"
            ]
        },
        Syscall {
            number: 22,
            name: "pipe",
            args: vec![
                "int *fildes"
            ]
        },
        Syscall {
            number: 23,
            name: "select",
            args: vec![
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
            args: vec![]
        },
        Syscall {
            number: 25,
            name: "mremap",
            args: vec![
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
            args: vec![
                "unsigned long start",
                "size_t len",
                "int flags"
            ]
        },
        Syscall {
            number: 27,
            name: "mincore",
            args: vec![
                "unsigned long start",
                "size_t len",
                "unsigned char * vec"
            ]
        },
        Syscall {
            number: 28,
            name: "madvise",
            args: vec![
                "unsigned long start",
                "size_t len",
                "int behavior"
            ]
        },
        Syscall {
            number: 29,
            name: "shmget",
            args: vec![
                "key_t key",
                "size_t size",
                "int flag"
            ]
        },
        Syscall {
            number: 30,
            name: "shmat",
            args: vec![
                "int shmid",
                "char *shmaddr",
                "int shmflg"
            ]
        },
        Syscall {
            number: 31,
            name: "shmctl",
            args: vec![
                "int shmid",
                "int cmd",
                "struct shmid_ds *buf"
            ]
        },
        Syscall {
            number: 32,
            name: "dup",
            args: vec![
                "unsigned int fildes"
            ]
        },
        Syscall {
            number: 33,
            name: "dup2",
            args: vec![
                "unsigned int oldfd",
                "unsigned int newfd"
            ]
        },
        Syscall {
            number: 34,
            name: "pause",
            args: vec![]
        },
        Syscall {
            number: 35,
            name: "nanosleep",
            args: vec![
                "struct __kernel_timespec *rqtp",
                "struct __kernel_timespec *rmtp"
            ]
        },
        Syscall {
            number: 36,
            name: "getitimer",
            args: vec![
                "int which",
                "struct itimerval *value"
            ]
        },
        Syscall {
            number: 37,
            name: "alarm",
            args: vec![
                "unsigned int seconds"
            ]
        },
        Syscall {
            number: 38,
            name: "setitimer",
            args: vec![
                "int which",
                "struct itimerval *value",
                "struct itimerval *ovalue"
            ]
        },
        Syscall {
            number: 39,
            name: "getpid",
            args: vec![]
        },
        Syscall {
            number: 40,
            name: "sendfile",
            args: vec![
                "int out_fd",
                "int in_fd",
                "off_t *offset",
                "size_t count"
            ]
        },
        Syscall {
            number: 41,
            name: "socket",
            args: vec![
                "int",
                "int",
                "int"
            ]
        },
        Syscall {
            number: 42,
            name: "connect",
            args: vec![
                "int",
                "struct sockaddr *",
                "int"
            ]
        },
        Syscall {
            number: 43,
            name: "accept",
            args: vec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 44,
            name: "sendto",
            args: vec![
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
            args: vec![
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
            args: vec![
                "int fd",
                "struct user_msghdr *msg",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 47,
            name: "recvmsg",
            args: vec![
                "int fd",
                "struct user_msghdr *msg",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 48,
            name: "shutdown",
            args: vec![
                "int",
                "int"
            ]
        },
        Syscall {
            number: 49,
            name: "bind",
            args: vec![
                "int",
                "struct sockaddr *",
                "int"
            ]
        },
        Syscall {
            number: 50,
            name: "listen",
            args: vec![
                "int",
                "int"
            ]
        },
        Syscall {
            number: 51,
            name: "getsockname",
            args: vec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 52,
            name: "getpeername",
            args: vec![
                "int",
                "struct sockaddr *",
                "int *"
            ]
        },
        Syscall {
            number: 53,
            name: "socketpair",
            args: vec![
                "int",
                "int",
                "int",
                "int *"
            ]
        },
        Syscall {
            number: 54,
            name: "setsockopt",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![]
        },
        Syscall {
            number: 58,
            name: "vfork",
            args: vec![]
        },
        Syscall {
            number: 59,
            name: "execve",
            args: vec![
                "const char *filename",
                "const char *const *argv",
                "const char *const *envp"
            ]
        },
        Syscall {
            number: 60,
            name: "exit",
            args: vec![
                "int error_code"
            ]
        },
        Syscall {
            number: 61,
            name: "wait4",
            args: vec![
                "pid_t pid",
                "int *stat_addr",
                "int options",
                "struct rusage *ru"
            ]
        },
        Syscall {
            number: 62,
            name: "kill",
            args: vec![
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 63,
            name: "uname",
            args: vec![
                "struct old_utsname *"
            ]
        },
        Syscall {
            number: 64,
            name: "semget",
            args: vec![
                "key_t key",
                "int nsems",
                "int semflg"
            ]
        },
        Syscall {
            number: 65,
            name: "semop",
            args: vec![
                "int semid",
                "struct sembuf *sops",
                "unsigned nsops"
            ]
        },
        Syscall {
            number: 66,
            name: "semctl",
            args: vec![
                "int semid",
                "int semnum",
                "int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 67,
            name: "shmdt",
            args: vec![
                "char *shmaddr"
            ]
        },
        Syscall {
            number: 68,
            name: "msgget",
            args: vec![
                "key_t key",
                "int msgflg"
            ]
        },
        Syscall {
            number: 69,
            name: "msgsnd",
            args: vec![
                "int msqid",
                "struct msgbuf *msgp",
                "size_t msgsz",
                "int msgflg"
            ]
        },
        Syscall {
            number: 70,
            name: "msgrcv",
            args: vec![
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
            args: vec![
                "int msqid",
                "int cmd",
                "struct msqid_ds *buf"
            ]
        },
        Syscall {
            number: 72,
            name: "fcntl",
            args: vec![
                "unsigned int fd",
                "unsigned int cmd",
                "unsigned long arg"
            ]
        },
        Syscall {
            number: 73,
            name: "flock",
            args: vec![
                "unsigned int fd",
                "unsigned int cmd"
            ]
        },
        Syscall {
            number: 74,
            name: "fsync",
            args: vec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 75,
            name: "fdatasync",
            args: vec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 76,
            name: "truncate",
            args: vec![
                "const char *path",
                "long length"
            ]
        },
        Syscall {
            number: 77,
            name: "ftruncate",
            args: vec![
                "unsigned int fd",
                "unsigned long length"
            ]
        },
        Syscall {
            number: 78,
            name: "getdents",
            args: vec![
                "unsigned int fd",
                "struct linux_dirent *dirent",
                "unsigned int count"
            ]
        },
        Syscall {
            number: 79,
            name: "getcwd",
            args: vec![
                "char *buf",
                "unsigned long size"
            ]
        },
        Syscall {
            number: 80,
            name: "chdir",
            args: vec![
                "const char *filename"
            ]
        },
        Syscall {
            number: 81,
            name: "fchdir",
            args: vec![
                "unsigned int fd"
            ]
        },
        Syscall {
            number: 82,
            name: "rename",
            args: vec![
                "const char *oldname",
                "const char *newname"
            ]
        },
        Syscall {
            number: 83,
            name: "mkdir",
            args: vec![
                "const char *pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 84,
            name: "rmdir",
            args: vec![
                "const char *pathname"
            ]
        },
        Syscall {
            number: 85,
            name: "creat",
            args: vec![
                "const char *pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 86,
            name: "link",
            args: vec![
                "const char *oldname",
                "const char *newname"
            ]
        },
        Syscall {
            number: 87,
            name: "unlink",
            args: vec![
                "const char *pathname"
            ]
        },
        Syscall {
            number: 88,
            name: "symlink",
            args: vec![
                "const char *old",
                "const char *new"
            ]
        },
        Syscall {
            number: 89,
            name: "readlink",
            args: vec![
                "const char *path",
                "char *buf",
                "int bufsiz"
            ]
        },
        Syscall {
            number: 90,
            name: "chmod",
            args: vec![
                "const char *filename",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 91,
            name: "fchmod",
            args: vec![
                "unsigned int fd",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 92,
            name: "chown",
            args: vec![
                "const char *filename",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 93,
            name: "fchown",
            args: vec![
                "unsigned int fd",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 94,
            name: "lchown",
            args: vec![
                "const char *filename",
                "uid_t user",
                "gid_t group"
            ]
        },
        Syscall {
            number: 95,
            name: "umask",
            args: vec![
                "int mask"
            ]
        },
        Syscall {
            number: 96,
            name: "gettimeofday",
            args: vec![
                "struct timeval *tv",
                "struct timezone *tz"
            ]
        },
        Syscall {
            number: 97,
            name: "getrlimit",
            args: vec![
                "unsigned int resource",
                "struct rlimit *rlim"
            ]
        },
        Syscall {
            number: 98,
            name: "getrusage",
            args: vec![
                "int who",
                "struct rusage *ru"
            ]
        },
        Syscall {
            number: 99,
            name: "sysinfo",
            args: vec![
                "struct sysinfo *info"
            ]
        },
        Syscall {
            number: 100,
            name: "times",
            args: vec![
                "struct tms *tbuf"
            ]
        },
        Syscall {
            number: 101,
            name: "ptrace",
            args: vec![
                "long request",
                "long pid",
                "unsigned long addr",
                "unsigned long data"
            ]
        },
        Syscall {
            number: 102,
            name: "getuid",
            args: vec![]
        },
        Syscall {
            number: 103,
            name: "syslog",
            args: vec![
                "int type",
                "char *buf",
                "int len"
            ]
        },
        Syscall {
            number: 104,
            name: "getgid",
            args: vec![]
        },
        Syscall {
            number: 105,
            name: "setuid",
            args: vec![
                "uid_t uid"
            ]
        },
        Syscall {
            number: 106,
            name: "setgid",
            args: vec![
                "gid_t gid"
            ]
        },
        Syscall {
            number: 107,
            name: "geteuid",
            args: vec![]
        },
        Syscall {
            number: 108,
            name: "getegid",
            args: vec![]
        },
        Syscall {
            number: 109,
            name: "setpgid",
            args: vec![
                "pid_t pid",
                "pid_t pgid"
            ]
        },
        Syscall {
            number: 110,
            name: "getppid",
            args: vec![]
        },
        Syscall {
            number: 111,
            name: "getpgrp",
            args: vec![]
        },
        Syscall {
            number: 112,
            name: "setsid",
            args: vec![]
        },
        Syscall {
            number: 113,
            name: "setreuid",
            args: vec![
                "uid_t ruid",
                "uid_t euid"
            ]
        },
        Syscall {
            number: 114,
            name: "setregid",
            args: vec![
                "gid_t rgid",
                "gid_t egid"
            ]
        },
        Syscall {
            number: 115,
            name: "getgroups",
            args: vec![
                "int gidsetsize",
                "gid_t *grouplist"
            ]
        },
        Syscall {
            number: 116,
            name: "setgroups",
            args: vec![
                "int gidsetsize",
                "gid_t *grouplist"
            ]
        },
        Syscall {
            number: 117,
            name: "setresuid",
            args: vec![
                "uid_t ruid",
                "uid_t euid",
                "uid_t suid"
            ]
        },
        Syscall {
            number: 118,
            name: "getresuid",
            args: vec![
                "uid_t *ruid",
                "uid_t *euid",
                "uid_t *suid"
            ]
        },
        Syscall {
            number: 119,
            name: "setresgid",
            args: vec![
                "gid_t rgid",
                "gid_t egid",
                "gid_t sgid"
            ]
        },
        Syscall {
            number: 120,
            name: "getresgid",
            args: vec![
                "gid_t *rgid",
                "gid_t *egid",
                "gid_t *sgid"
            ]
        },
        Syscall {
            number: 121,
            name: "getpgid",
            args: vec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 122,
            name: "setfsuid",
            args: vec![
                "uid_t uid"
            ]
        },
        Syscall {
            number: 123,
            name: "setfsgid",
            args: vec![
                "gid_t gid"
            ]
        },
        Syscall {
            number: 124,
            name: "getsid",
            args: vec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 125,
            name: "capget",
            args: vec![
                "cap_user_header_t header",
                "cap_user_data_t dataptr"
            ]
        },
        Syscall {
            number: 126,
            name: "capset",
            args: vec![
                "cap_user_header_t header",
                "const cap_user_data_t data"
            ]
        },
        Syscall {
            number: 127,
            name: "rt_sigpending",
            args: vec![
                "sigset_t *set",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 128,
            name: "rt_sigtimedwait",
            args: vec![
                "const sigset_t *uthese",
                "siginfo_t *uinfo",
                "const struct __kernel_timespec *uts",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 129,
            name: "rt_sigqueueinfo",
            args: vec![
                "pid_t pid",
                "int sig",
                "siginfo_t *uinfo"
            ]
        },
        Syscall {
            number: 130,
            name: "rt_sigsuspend",
            args: vec![
                "sigset_t *unewset",
                "size_t sigsetsize"
            ]
        },
        Syscall {
            number: 131,
            name: "sigaltstack",
            args: vec![
                "const struct sigaltstack *uss",
                "struct sigaltstack *uoss"
            ]
        },
        Syscall {
            number: 132,
            name: "utime",
            args: vec![
                "char *filename",
                "struct utimbuf *times"
            ]
        },
        Syscall {
            number: 133,
            name: "mknod",
            args: vec![
                "const char *filename",
                "umode_t mode",
                "unsigned dev"
            ]
        },
        Syscall {
            number: 134,
            name: "uselib",
            args: vec![
                "const char *library"
            ]
        },
        Syscall {
            number: 135,
            name: "personality",
            args: vec![
                "unsigned int personality"
            ]
        },
        Syscall {
            number: 136,
            name: "ustat",
            args: vec![
                "unsigned dev",
                "struct ustat *ubuf"
            ]
        },
        Syscall {
            number: 137,
            name: "statfs",
            args: vec![
                "const char * path",
                "struct statfs *buf"
            ]
        },
        Syscall {
            number: 138,
            name: "fstatfs",
            args: vec![
                "unsigned int fd",
                "struct statfs *buf"
            ]
        },
        Syscall {
            number: 139,
            name: "sysfs",
            args: vec![
                "int option",
                "unsigned long arg1",
                "unsigned long arg2"
            ]
        },
        Syscall {
            number: 140,
            name: "getpriority",
            args: vec![
                "int which",
                "int who"
            ]
        },
        Syscall {
            number: 141,
            name: "setpriority",
            args: vec![
                "int which",
                "int who",
                "int niceval"
            ]
        },
        Syscall {
            number: 142,
            name: "sched_setparam",
            args: vec![
                "pid_t pid",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 143,
            name: "sched_getparam",
            args: vec![
                "pid_t pid",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 144,
            name: "sched_setscheduler",
            args: vec![
                "pid_t pid",
                "int policy",
                "struct sched_param *param"
            ]
        },
        Syscall {
            number: 145,
            name: "sched_getscheduler",
            args: vec![
                "pid_t pid"
            ]
        },
        Syscall {
            number: 146,
            name: "sched_get_priority_max",
            args: vec![
                "int policy"
            ]
        },
        Syscall {
            number: 147,
            name: "sched_get_priority_min",
            args: vec![
                "int policy"
            ]
        },
        Syscall {
            number: 148,
            name: "sched_rr_get_interval",
            args: vec![
                "pid_t pid",
                "struct __kernel_timespec *interval"
            ]
        },
        Syscall {
            number: 149,
            name: "mlock",
            args: vec![
                "unsigned long start",
                "size_t len"
            ]
        },
        Syscall {
            number: 150,
            name: "munlock",
            args: vec![
                "unsigned long start",
                "size_t len"
            ]
        },
        Syscall {
            number: 151,
            name: "mlockall",
            args: vec![
                "int flags"
            ]
        },
        Syscall {
            number: 152,
            name: "munlockall",
            args: vec![]
        },
        Syscall {
            number: 153,
            name: "vhangup",
            args: vec![]
        },
        Syscall {
            number: 154,
            name: "modify_ldt",
            args: vec![
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
            args: vec![
                "const char *new_root",
                "const char *put_old"
            ]
        },
        Syscall {
            number: 156,
            name: "_sysctl",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
                "struct __kernel_timex *txc_p"
            ]
        },
        Syscall {
            number: 160,
            name: "setrlimit",
            args: vec![
                "unsigned int resource",
                "struct rlimit *rlim"
            ]
        },
        Syscall {
            number: 161,
            name: "chroot",
            args: vec![
                "const char *filename"
            ]
        },
        Syscall {
            number: 162,
            name: "sync",
            args: vec![]
        },
        Syscall {
            number: 163,
            name: "acct",
            args: vec![
                "const char *name"
            ]
        },
        Syscall {
            number: 164,
            name: "settimeofday",
            args: vec![
                "struct timeval *tv",
                "struct timezone *tz"
            ]
        },
        Syscall {
            number: 165,
            name: "mount",
            args: vec![
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
            args: vec![
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
            args: vec![
                "const char *specialfile",
                "int swap_flags"
            ]
        },
        Syscall {
            number: 168,
            name: "swapoff",
            args: vec![
                "const char *specialfile"
            ]
        },
        Syscall {
            number: 169,
            name: "reboot",
            args: vec![
                "int magic1",
                "int magic2",
                "unsigned int cmd",
                "void *arg"
            ]
        },
        Syscall {
            number: 170,
            name: "sethostname",
            args: vec![
                "char *name",
                "int len"
            ]
        },
        Syscall {
            number: 171,
            name: "setdomainname",
            args: vec![
                "char *name",
                "int len"
            ]
        },
        Syscall {
            number: 172,
            name: "iopl",
            args: vec![
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
            args: vec![
                "unsigned long from",
                "unsigned long num",
                "int on"
            ]
        },
        Syscall {
            number: 174,
            name: "create_module",
            args: vec![
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
            args: vec![
                "void *umod",
                "unsigned long len",
                "const char *uargs"
            ]
        },
        Syscall {
            number: 176,
            name: "delete_module",
            args: vec![
                "const char *name_user",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 177,
            name: "get_kernel_syms",
            args: vec![
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
            args: vec![
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
            args: vec![
                "unsigned int cmd",
                "const char *special",
                "qid_t id",
                "void *addr"
            ]
        },
        Syscall {
            number: 180,
            name: "nfsservctl",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![]
        },
        Syscall {
            number: 187,
            name: "readahead",
            args: vec![
                "int fd",
                "loff_t offset",
                "size_t count"
            ]
        },
        Syscall {
            number: 188,
            name: "setxattr",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
                "const char *path",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 192,
            name: "lgetxattr",
            args: vec![
                "const char *path",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 193,
            name: "fgetxattr",
            args: vec![
                "int fd",
                "const char *name",
                "void *value",
                "size_t size"
            ]
        },
        Syscall {
            number: 194,
            name: "listxattr",
            args: vec![
                "const char *path",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 195,
            name: "llistxattr",
            args: vec![
                "const char *path",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 196,
            name: "flistxattr",
            args: vec![
                "int fd",
                "char *list",
                "size_t size"
            ]
        },
        Syscall {
            number: 197,
            name: "removexattr",
            args: vec![
                "const char *path",
                "const char *name"
            ]
        },
        Syscall {
            number: 198,
            name: "lremovexattr",
            args: vec![
                "const char *path",
                "const char *name"
            ]
        },
        Syscall {
            number: 199,
            name: "fremovexattr",
            args: vec![
                "int fd",
                "const char *name"
            ]
        },
        Syscall {
            number: 200,
            name: "tkill",
            args: vec![
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 201,
            name: "time",
            args: vec![
                "time_t *tloc"
            ]
        },
        Syscall {
            number: 202,
            name: "futex",
            args: vec![
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
            args: vec![
                "pid_t pid",
                "unsigned int len",
                "unsigned long *user_mask_ptr"
            ]
        },
        Syscall {
            number: 204,
            name: "sched_getaffinity",
            args: vec![
                "pid_t pid",
                "unsigned int len",
                "unsigned long *user_mask_ptr"
            ]
        },
        Syscall {
            number: 205,
            name: "set_thread_area",
            args: vec![
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
            args: vec![
                "unsigned nr_reqs",
                "aio_context_t *ctx"
            ]
        },
        Syscall {
            number: 207,
            name: "io_destroy",
            args: vec![
                "aio_context_t ctx"
            ]
        },
        Syscall {
            number: 208,
            name: "io_getevents",
            args: vec![
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
            args: vec![
                "aio_context_t",
                "long",
                "struct iocb * *"
            ]
        },
        Syscall {
            number: 210,
            name: "io_cancel",
            args: vec![
                "aio_context_t ctx_id",
                "struct iocb *iocb",
                "struct io_event *result"
            ]
        },
        Syscall {
            number: 211,
            name: "get_thread_area",
            args: vec![
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
            args: vec![
                "u64 cookie64",
                "char *buf",
                "size_t len"
            ]
        },
        Syscall {
            number: 213,
            name: "epoll_create",
            args: vec![
                "int size"
            ]
        },
        Syscall {
            number: 214,
            name: "epoll_ctl_old",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
                "unsigned int fd",
                "struct linux_dirent64 *dirent",
                "unsigned int count"
            ]
        },
        Syscall {
            number: 218,
            name: "set_tid_address",
            args: vec![
                "int *tidptr"
            ]
        },
        Syscall {
            number: 219,
            name: "restart_syscall",
            args: vec![]
        },
        Syscall {
            number: 220,
            name: "semtimedop",
            args: vec![
                "int semid",
                "struct sembuf *sops",
                "unsigned nsops",
                "const struct __kernel_timespec *timeout"
            ]
        },
        Syscall {
            number: 221,
            name: "fadvise64",
            args: vec![
                "int fd",
                "loff_t offset",
                "size_t len",
                "int advice"
            ]
        },
        Syscall {
            number: 222,
            name: "timer_create",
            args: vec![
                "clockid_t which_clock",
                "struct sigevent *timer_event_spec",
                "timer_t * created_timer_id"
            ]
        },
        Syscall {
            number: 223,
            name: "timer_settime",
            args: vec![
                "timer_t timer_id",
                "int flags",
                "const struct __kernel_itimerspec *new_setting",
                "struct __kernel_itimerspec *old_setting"
            ]
        },
        Syscall {
            number: 224,
            name: "timer_gettime",
            args: vec![
                "timer_t timer_id",
                "struct __kernel_itimerspec *setting"
            ]
        },
        Syscall {
            number: 225,
            name: "timer_getoverrun",
            args: vec![
                "timer_t timer_id"
            ]
        },
        Syscall {
            number: 226,
            name: "timer_delete",
            args: vec![
                "timer_t timer_id"
            ]
        },
        Syscall {
            number: 227,
            name: "clock_settime",
            args: vec![
                "clockid_t which_clock",
                "const struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 228,
            name: "clock_gettime",
            args: vec![
                "clockid_t which_clock",
                "struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 229,
            name: "clock_getres",
            args: vec![
                "clockid_t which_clock",
                "struct __kernel_timespec *tp"
            ]
        },
        Syscall {
            number: 230,
            name: "clock_nanosleep",
            args: vec![
                "clockid_t which_clock",
                "int flags",
                "const struct __kernel_timespec *rqtp",
                "struct __kernel_timespec *rmtp"
            ]
        },
        Syscall {
            number: 231,
            name: "exit_group",
            args: vec![
                "int error_code"
            ]
        },
        Syscall {
            number: 232,
            name: "epoll_wait",
            args: vec![
                "int epfd",
                "struct epoll_event *events",
                "int maxevents",
                "int timeout"
            ]
        },
        Syscall {
            number: 233,
            name: "epoll_ctl",
            args: vec![
                "int epfd",
                "int op",
                "int fd",
                "struct epoll_event *event"
            ]
        },
        Syscall {
            number: 234,
            name: "tgkill",
            args: vec![
                "pid_t tgid",
                "pid_t pid",
                "int sig"
            ]
        },
        Syscall {
            number: 235,
            name: "utimes",
            args: vec![
                "char *filename",
                "struct timeval *utimes"
            ]
        },
        Syscall {
            number: 236,
            name: "vserver",
            args: vec![
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
            args: vec![
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
            args: vec![
                "int mode",
                "const unsigned long *nmask",
                "unsigned long maxnode"
            ]
        },
        Syscall {
            number: 239,
            name: "get_mempolicy",
            args: vec![
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
            args: vec![
                "const char *name",
                "int oflag",
                "umode_t mode",
                "struct mq_attr *attr"
            ]
        },
        Syscall {
            number: 241,
            name: "mq_unlink",
            args: vec![
                "const char *name"
            ]
        },
        Syscall {
            number: 242,
            name: "mq_timedsend",
            args: vec![
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
            args: vec![
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
            args: vec![
                "mqd_t mqdes",
                "const struct sigevent *notification"
            ]
        },
        Syscall {
            number: 245,
            name: "mq_getsetattr",
            args: vec![
                "mqd_t mqdes",
                "const struct mq_attr *mqstat",
                "struct mq_attr *omqstat"
            ]
        },
        Syscall {
            number: 246,
            name: "kexec_load",
            args: vec![
                "unsigned long entry",
                "unsigned long nr_segments",
                "struct kexec_segment *segments",
                "unsigned long flags"
            ]
        },
        Syscall {
            number: 247,
            name: "waitid",
            args: vec![
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
            args: vec![
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
            args: vec![
                "const char *_type",
                "const char *_description",
                "const char *_callout_info",
                "key_serial_t destringid"
            ]
        },
        Syscall {
            number: 250,
            name: "keyctl",
            args: vec![
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
            args: vec![
                "int which",
                "int who",
                "int ioprio"
            ]
        },
        Syscall {
            number: 252,
            name: "ioprio_get",
            args: vec![
                "int which",
                "int who"
            ]
        },
        Syscall {
            number: 253,
            name: "inotify_init",
            args: vec![]
        },
        Syscall {
            number: 254,
            name: "inotify_add_watch",
            args: vec![
                "int fd",
                "const char *path",
                "u32 mask"
            ]
        },
        Syscall {
            number: 255,
            name: "inotify_rm_watch",
            args: vec![
                "int fd",
                "__s32 wd"
            ]
        },
        Syscall {
            number: 256,
            name: "migrate_pages",
            args: vec![
                "pid_t pid",
                "unsigned long maxnode",
                "const unsigned long *from",
                "const unsigned long *to"
            ]
        },
        Syscall {
            number: 257,
            name: "openat",
            args: vec![
                "int dfd",
                "const char *filename",
                "int flags",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 258,
            name: "mkdirat",
            args: vec![
                "int dfd",
                "const char * pathname",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 259,
            name: "mknodat",
            args: vec![
                "int dfd",
                "const char * filename",
                "umode_t mode",
                "unsigned dev"
            ]
        },
        Syscall {
            number: 260,
            name: "fchownat",
            args: vec![
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
            args: vec![
                "int dfd",
                "const char *filename",
                "struct timeval *utimes"
            ]
        },
        Syscall {
            number: 262,
            name: "newfstatat",
            args: vec![
                "int dfd",
                "const char *filename",
                "struct stat *statbuf",
                "int flag"
            ]
        },
        Syscall {
            number: 263,
            name: "unlinkat",
            args: vec![
                "int dfd",
                "const char * pathname",
                "int flag"
            ]
        },
        Syscall {
            number: 264,
            name: "renameat",
            args: vec![
                "int olddfd",
                "const char * oldname",
                "int newdfd",
                "const char * newname"
            ]
        },
        Syscall {
            number: 265,
            name: "linkat",
            args: vec![
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
            args: vec![
                "const char * oldname",
                "int newdfd",
                "const char * newname"
            ]
        },
        Syscall {
            number: 267,
            name: "readlinkat",
            args: vec![
                "int dfd",
                "const char *path",
                "char *buf",
                "int bufsiz"
            ]
        },
        Syscall {
            number: 268,
            name: "fchmodat",
            args: vec![
                "int dfd",
                "const char * filename",
                "umode_t mode"
            ]
        },
        Syscall {
            number: 269,
            name: "faccessat",
            args: vec![
                "int dfd",
                "const char *filename",
                "int mode"
            ]
        },
        Syscall {
            number: 270,
            name: "pselect6",
            args: vec![
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
            args: vec![
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
            args: vec![
                "unsigned long unshare_flags"
            ]
        },
        Syscall {
            number: 273,
            name: "set_robust_list",
            args: vec![
                "struct robust_list_head *head",
                "size_t len"
            ]
        },
        Syscall {
            number: 274,
            name: "get_robust_list",
            args: vec![
                "int pid",
                "struct robust_list_head * *head_ptr",
                "size_t *len_ptr"
            ]
        },
        Syscall {
            number: 275,
            name: "splice",
            args: vec![
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
            args: vec![
                "int fdin",
                "int fdout",
                "size_t len",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 277,
            name: "sync_file_range",
            args: vec![
                "int fd",
                "loff_t offset",
                "loff_t nbytes",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 278,
            name: "vmsplice",
            args: vec![
                "int fd",
                "const struct iovec *iov",
                "unsigned long nr_segs",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 279,
            name: "move_pages",
            args: vec![
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
            args: vec![
                "int dfd",
                "const char *filename",
                "struct __kernel_timespec *utimes",
                "int flags"
            ]
        },
        Syscall {
            number: 281,
            name: "epoll_pwait",
            args: vec![
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
            args: vec![
                "int ufd",
                "sigset_t *user_mask",
                "size_t sizemask"
            ]
        },
        Syscall {
            number: 283,
            name: "timerfd_create",
            args: vec![
                "int clockid",
                "int flags"
            ]
        },
        Syscall {
            number: 284,
            name: "eventfd",
            args: vec![
                "unsigned int count"
            ]
        },
        Syscall {
            number: 285,
            name: "fallocate",
            args: vec![
                "int fd",
                "int mode",
                "loff_t offset",
                "loff_t len"
            ]
        },
        Syscall {
            number: 286,
            name: "timerfd_settime",
            args: vec![
                "int ufd",
                "int flags",
                "const struct __kernel_itimerspec *utmr",
                "struct __kernel_itimerspec *otmr"
            ]
        },
        Syscall {
            number: 287,
            name: "timerfd_gettime",
            args: vec![
                "int ufd",
                "struct __kernel_itimerspec *otmr"
            ]
        },
        Syscall {
            number: 288,
            name: "accept4",
            args: vec![
                "int",
                "struct sockaddr *",
                "int *",
                "int"
            ]
        },
        Syscall {
            number: 289,
            name: "signalfd4",
            args: vec![
                "int ufd",
                "sigset_t *user_mask",
                "size_t sizemask",
                "int flags"
            ]
        },
        Syscall {
            number: 290,
            name: "eventfd2",
            args: vec![
                "unsigned int count",
                "int flags"
            ]
        },
        Syscall {
            number: 291,
            name: "epoll_create1",
            args: vec![
                "int flags"
            ]
        },
        Syscall {
            number: 292,
            name: "dup3",
            args: vec![
                "unsigned int oldfd",
                "unsigned int newfd",
                "int flags"
            ]
        },
        Syscall {
            number: 293,
            name: "pipe2",
            args: vec![
                "int *fildes",
                "int flags"
            ]
        },
        Syscall {
            number: 294,
            name: "inotify_init1",
            args: vec![
                "int flags"
            ]
        },
        Syscall {
            number: 295,
            name: "preadv",
            args: vec![
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
            args: vec![
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
            args: vec![
                "pid_t tgid",
                "pid_t pid",
                "int sig",
                "siginfo_t *uinfo"
            ]
        },
        Syscall {
            number: 298,
            name: "perf_event_open",
            args: vec![
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
            args: vec![
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
            args: vec![
                "unsigned int flags",
                "unsigned int event_f_flags"
            ]
        },
        Syscall {
            number: 301,
            name: "fanotify_mark",
            args: vec![
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
            args: vec![
                "pid_t pid",
                "unsigned int resource",
                "const struct rlimit64 *new_rlim",
                "struct rlimit64 *old_rlim"
            ]
        },
        Syscall {
            number: 303,
            name: "name_to_handle_at",
            args: vec![
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
            args: vec![
                "int mountdirfd",
                "struct file_handle *handle",
                "int flags"
            ]
        },
        Syscall {
            number: 305,
            name: "clock_adjtime",
            args: vec![
                "clockid_t which_clock",
                "struct __kernel_timex *tx"
            ]
        },
        Syscall {
            number: 306,
            name: "syncfs",
            args: vec![
                "int fd"
            ]
        },
        Syscall {
            number: 307,
            name: "sendmmsg",
            args: vec![
                "int fd",
                "struct mmsghdr *msg",
                "unsigned int vlen",
                "unsigned flags"
            ]
        },
        Syscall {
            number: 308,
            name: "setns",
            args: vec![
                "int fd",
                "int nstype"
            ]
        },
        Syscall {
            number: 309,
            name: "getcpu",
            args: vec![
                "unsigned *cpu",
                "unsigned *node",
                "struct getcpu_cache *cache"
            ]
        },
        Syscall {
            number: 310,
            name: "process_vm_readv",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
                "int fd",
                "const char *uargs",
                "int flags"
            ]
        },
        Syscall {
            number: 314,
            name: "sched_setattr",
            args: vec![
                "pid_t pid",
                "struct sched_attr *attr",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 315,
            name: "sched_getattr",
            args: vec![
                "pid_t pid",
                "struct sched_attr *attr",
                "unsigned int size",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 316,
            name: "renameat2",
            args: vec![
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
            args: vec![
                "unsigned int op",
                "unsigned int flags",
                "void *uargs"
            ]
        },
        Syscall {
            number: 318,
            name: "getrandom",
            args: vec![
                "char *buf",
                "size_t count",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 319,
            name: "memfd_create",
            args: vec![
                "const char *uname_ptr",
                "unsigned int flags"
            ]
        },
        Syscall {
            number: 320,
            name: "kexec_file_load",
            args: vec![
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
            args: vec![
                "int cmd",
                "union bpf_attr *attr",
                "unsigned int size"
            ]
        },
        Syscall {
            number: 322,
            name: "execveat",
            args: vec![
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
            args: vec![
                "int flags"
            ]
        },
        Syscall {
            number: 324,
            name: "membarrier",
            args: vec![
                "int cmd",
                "int flags"
            ]
        },
        Syscall {
            number: 325,
            name: "mlock2",
            args: vec![
                "unsigned long start",
                "size_t len",
                "int flags"
            ]
        },
        Syscall {
            number: 326,
            name: "copy_file_range",
            args: vec![
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
            args: vec![
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
            args: vec![
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
            args: vec![
                "unsigned long start",
                "size_t len",
                "unsigned long prot",
                "int pkey"
            ]
        },
        Syscall {
            number: 330,
            name: "pkey_alloc",
            args: vec![
                "unsigned long flags",
                "unsigned long init_val"
            ]
        },
        Syscall {
            number: 331,
            name: "pkey_free",
            args: vec![
                "int pkey"
            ]
        },
        Syscall {
            number: 332,
            name: "statx",
            args: vec![
                "int dfd",
                "const char *path",
                "unsigned flags",
                "unsigned mask",
                "struct statx *buffer"
            ]
        }
    ];
}
