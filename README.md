# confine

Strong security-focused process tracer with stronger capabilities

## Introduction

__confine__ is a strong security-focused process tracer with even stronger capabilities. At a low-level it is a performant eBPF-based (`s`/`l`)`trace` clone, but at a higher level it provides support for invaluable features including:

* OCI-complaint policy generation using custom trace filters
	* Provides higher-level configuration abstraction for seccomp, AppArmor, SELinux
* Userspace Policy enforcement on tracee processes
	* Tracee processes are isolated and sandboxed based on applied filter

