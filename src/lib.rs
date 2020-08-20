//! Main library interface to confine, mainly used by the confine CLI
//! tool interfaces. Implements the following functionality:
//!
//!  - syscall and userspace func tracing with two modes of functionality
//!  - deserialization support for traces to serializable formats
//!  - policy parsing and generation
//!  - enforcer API for policy generation and enforcement

pub mod error;
pub mod policy;
pub mod syscall;
pub mod enforcers;

mod ptrace;
pub mod trace;
