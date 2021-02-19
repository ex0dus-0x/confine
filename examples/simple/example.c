/*
 * example.c
 *
 *      Smoke test sample that demonstrates a bunch of malware capabilities
 *      and functionalities to better test `confine`
 */
#include <stdio.h>
#include <unistd.h>

#include <sys/ptrace.h>

#define BUFSIZE 1024

int main(void)
{
    // anti-debug
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0))
        printf("Caught the debugger!\n");

    char hostname[BUFSIZE];
    hostname[BUFSIZE - 1] = '\0';
    gethostname(hostname, BUFSIZE - 1);
    printf("%s\n", hostname);
    return 0;
}
