/*
 * template.c
 *
 *		Template bcc function that parses out function arguments when hooked to a specific
 *		system or library call.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_PERF_OUTPUT(events);

/*
 * kprobe callback routine that is attached to each system call. {SYSCALL} represents
 * name of the syscall as parsed out in unistd.h. Parses out parameter content through
 * `ptrace` PT_REGS routines.
 */
int kprobe__{SYSCALL}(struct pt_regs *ctx)
{
	/* TODO: syscall content in struct */
	bpf_trace_printk("syscall!\n");
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
};
