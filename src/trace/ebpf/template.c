/*
 * template.c
 *
 *		Template bcc function that parses out function arguments when hooked to a specific
 *		system or library call. Includes kprobe callback routine that is attached to each
 *		system call. {SYSCALL} represents name of the syscall as parsed out in unistd.h. Parses
 *		out parameter content through `ptrace` PT_REGS routines.
 *
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

#define BUF_SIZE 20

BPF_PERF_OUTPUT(events);

/* defines struct for encapsulating syscall trace information */
typedef struct {
	size_t arg1;
	char arg1_contents[BUF_SIZE];
	size_t arg2;
	size_t arg3;
} args_t;


int kprobe__SYSCALL(struct pt_regs *ctx)
{
	args_t data = {};
	data.arg3 = PT_REGS_PARM3(ctx);
	data.arg2 = PT_REGS_PARM2(ctx);
	data.arg1 = PT_REGS_PARM1(ctx);

	bpf_trace_printk("syscall!\n");
	bpf_probe_read(&data.arg1_contents,
		sizeof(data.arg1_contents), \
		(void *) data.arg1);

	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
};
