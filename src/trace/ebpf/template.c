/*
 * template.c
 *
 *		Template bcc function that parses out function arguments when hooked to a specific
 *		system or library call.
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>

struct key_t {
	long syscall_nr;
	u32 tid;
};


TRACEPOINT_PROBE(raw_syscalls, sys_enter) {


};


TRACEPOINT_PROBE(raw_syscalls, sys_exit) {


};
