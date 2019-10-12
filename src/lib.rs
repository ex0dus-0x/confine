//! lib.rs
//!
//!     Main library interface to confine, mainly used by the confine CLI
//!     tool interfaces. Implements the following functionality:
//!
//!      - syscall and userspace func tracing with two modes of functionality
//!      - deserialization support for traces to serializable formats
//!      - enforcer API for policy generation and enforcement

extern crate regex;
extern crate libc;
extern crate nix;
extern crate bcc;
extern crate goblin;

extern crate serde;
extern crate serde_json;

#[macro_use] extern crate log;
#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;

pub mod trace;
pub mod syscall;
pub mod logger;
