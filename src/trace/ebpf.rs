//! ebpf.rs
//!
//!     Implements helper functions for parsing bcc from template
//!     C files, and generating and loading eBPF as a result.

#[repr(C)]
struct data_t {
    libc_function: [u8; 20],
    arg1_contents: [u8; 20],
    arg1: size_t,
    arg2: size_t,
    arg3: size_t,
}
