//! lib.rs
//!
//!     Main library interface to confine, mainly used by the confine CLI
//!     tool interfaces. Implements the following functionality:
//!
//!      - syscall and userspace func tracing with two modes of functionality
//!      - deserialization support for traces to serializable formats
//!      - policy parsing and generation
//!      - enforcer API for policy generation and enforcement

extern crate regex;

extern crate libc;
extern crate bcc;
extern crate unshare;

extern crate serde;
extern crate serde_json;
extern crate serde_yaml;

#[macro_use] extern crate log;
#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;


/// logger used in both CLI and library modules for verbose debugging support.
pub mod logger;

/// defines interface to system call table generation and de/serialization.
pub mod syscall;

/// defines the `trace` submodule that includes support for interfacing tracing with
/// either ptrace or eBPF instrumentation, with high-level interfacing and trait bound defined in mod.rs
pub mod trace;

/// defines our common policy format, and its parser and enforcer generation procedures.
pub mod policy;

/// contains submodules for interfaces of security enforcers, with common trait bound defined in mod.rs
pub mod enforcers;
