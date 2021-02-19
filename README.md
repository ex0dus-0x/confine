<div align="center">
    <h1>confine</h1>
    <p>Containers, but for dynamic malware analysis</p>
</div>

[![Actions][actions-badge]][actions-url]

[actions-badge]: https://github.com/ex0dus-0x/confine/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/confine/actions

__confine__ is a container runtime for dynamically analyzing suspicious executables. Given a sample suspected of being malware, __confine__ will create a container mount,
dynamically trace it, and report back to you what threat indicators it has been able to find. No more clunky sandboxes and VMs!

## Features

* __Threat Detection__ - identifies common malware capabilities and behaviors using dynamic tracing!
* __Automated Builds__ - use `Confinement` policies to quickly provision an environment, and share it with other threat analysts!
* __Syscall Filtering__ - enforce rules upon system call behaviors to log metrics or block malicious behavior!

## Usage

### Installing 

To install `confine`, use `cargo`:

```
$ cargo install confine
```

### Running an Analysis

To dynamically analyze a sample, we must first create a workspace with a `Confinement` policy to
specify how our containerized environment will be provisioned. __confine__ can automatically do that for us:

```
$ confine new workspace/
```

Having a workspace is good for compartmentalizing other necessary dependencies that is used in the
container, whether its a locally built image, source code, configurations, etc.

A `Confinement` is __confine__'s version of a `Dockerfile`, but for provisioning container environments for tracing an executable.
See the [example here](https://github.com/ex0dus-0x/confine/blob/master/examples/simple/Confinement) for more details on how to configure it,
and set up syscall filtering rules as well.

Once everything is set, we can now execute an analysis! __confine__ will not only run a dynamic trace, but will also employ its set of detections
during execution, outputting the behaviors it encoutners in the end:

```
$ confine exec workspace/
a.out  example.c
Caught the debugger!
intelligent-rest-5105
[2021-02-19T04:21:56Z ERROR confine::trace::subprocess] confine: [BLOCK] encountered syscall exit_group
{
  "syscalls": [
    "brk",
    "access",
    "mmap",
    "access",
    "open",
    "fstat",
    "mmap",
    "close",
    "access",
    "open",
    "read",
    "fstat",
    "mmap",
    "mprotect",
    "mmap",
    "mmap",
    "close",
    "mmap",
    "mmap",
    "arch_prctl",
    "mprotect",
    "mprotect",
    "mprotect",
    "munmap",
    "ptrace",
    "fstat",
    "mmap",
    "write",
    "uname",
    "write"
  ],
  "strings": [
    "Caught the debugger!\n",
    "intelligent-rest-5105\n"
  ],
  "networking": [],
  "file_io": {
    "/lib/x86_64-linux-gnu/libc.so.6": "524288",
    "/etc/ld.so.cache": "524288"
  },
  "commands": [],
  "capabilities": {
    "evasion": {
      "stalling": false,
      "antidebug": true,
      "antisandbox": false,
      "process_infect": false
    },
    "persistence": {
      "init_persistence": false,
      "time_persistence": false,
      "config_persistence": false
    },
    "deception": false
  }
}
```

## License

[MIT License](https://codemuch.tech/docs/license.txt)
