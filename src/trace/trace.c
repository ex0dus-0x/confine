/* trace.c
 *
 * 		Standard bcc dependencies and struct holding
 *		system/library call parameter info
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    char libc_function[20];
    char arg1_contents[20];
    size_t arg1;
    size_t arg2;
    size_t arg3;
};
