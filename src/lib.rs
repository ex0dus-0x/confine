//! Main library interface to confine, mainly used by the confine CLI
//! tool interfaces. Implements the following functionality:
//!
//!  - syscall and userspace tracing
//!  - deserialization support for traces to serializable formats
//!  - policy parsing and enforcement

pub mod error;
pub mod policy;
pub mod syscall;
pub mod threat;
pub mod trace;
