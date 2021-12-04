#![no_std]
#![no_main]

use confine_probes::tracer::OpenPath;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut COMMAND_EXECS: PerfMap<CommandExec> = PerfMap::with_max_entries(1024);

#[map]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);

/*
 * Command Execution System Calls
 */

#[kprobe]
fn do_sys_execve(regs: Registers) {
    let mut exec = CommandExec::default();
    unsafe {
        let filename = regs.parm2() as *const u8;

        // read the path to program
        if bpf_probe_read_str(
            exec.path.as_mut_ptr() as *mut _,
            exec.path.len() as i32,
            filename as *const _,
        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
            return;
        }

        // read arguments
        if bpf_probe_read(

        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
            return;
        }
        COMMAND_EXECS.insert(regs.ctx, &exec);
    }
}

/*
 * File I/O System Calls
 */

#[kprobe]
fn do_sys_openat2(regs: Registers) {
    let mut path = OpenPath::default();
	unsafe {
        let filename = regs.parm2() as *const u8;
        if bpf_probe_read_str(
            path.filename.as_mut_ptr() as *mut _,
            path.filename.len() as i32,
            filename as *const _,
        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_str\0");
            return;
        }
        OPEN_PATHS.insert(regs.ctx, &path);
    }
}

/*
 * Other Interesting System Calls
 */

#[kprobe]
fn do_sys_memfd_create(regs: Registers) {
    let mut memfd = InMemory::default();
    unsafe {
        let filename = regs.parm2() as *const u8;
        if bpf_probe_read_str(

        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_str\0");
            return;
        }
    }
}
