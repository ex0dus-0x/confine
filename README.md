# confine

Security-focused firewall with policy handling capabilities

## Introduction

__confine__ is a security-focused syscall-based firewall  that supports generating policies for Linux security _enforcers_. Enforcers are defined as execution runtimes supported by the operating system that take a profile and conduct host-based policy enforcement, such as seccomp.

While Linux supports a lot of these well-documented security enforcers over the lifespan of the operating system, many of them have given up usability for the
ability to support fine-grained configurability, making them increasingly complex to write. __confine__ enables security and devops engineers to not only generate enforcer profiles
from a common configuration format, but also test these policies against actual applications under an unprivileged sandboxed environment. This not only enables
a user to improve security with intrusion detection and monitoring, but also fill in the complexity gap in hand-rolling security profiles for production environments.

## Features

* Fast system call tracing with either `ptrace` or EBPF mode (_WIP_)
  * Supports syscall trace serialization to JSON
  * Isolated process tracing with Linux namespaces and capabilities
* Policy generation for enforcer backends
  * Currently supports Docker seccomp profile generation

## Usage

To build:

```
$ cargo install
```

To run a normal execution trace:

```
$ confine -- mycommand [arg1] ...
```

To run a policy against an execution trace:

```
$ confine --policy mypolicy.toml -- mycommand [arg1]
```

To run a policy against a trace, and generate an enforcer profile:

```
$ confine --policy mypolicy.toml --enforcer seccomp -- mycommand [arg1]
```


## See also

* [Systrace](http://www.citi.umich.edu/u/provos/systrace/)
* [Twistlock](https://www.twistlock.com/2018/01/24/automated-policy-library-system-call-defense-2-3-deep-dive/)
* [Karn](https://github.com/grantseltzer/karn)
