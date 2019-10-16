/*
 * template.c
 *
 *		Template bcc function that parses out function arguments when hooked to a specific
 *		system or library call.
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>



BPF_PERF_OUTPUT(events);

int trace_fun_NAME(struct pt_regs *ctx) {
	struct data_t data = {};
	data.arg3 = PT_REGS_PARM3(ctx);
	data.arg2 = PT_REGS_PARM2(ctx);
	data.arg1 = PT_REGS_PARM1(ctx);

	bpf_probe_read(&data.arg1_contents, sizeof(data.arg1_contents), \
		(void *) data.arg1);

	strncpy(data.libc_function, "NAME", sizeof((char *) "NAME"));
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
};
