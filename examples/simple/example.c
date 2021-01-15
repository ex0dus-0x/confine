#include <stdio.h>
#include <unistd.h>

#define BUFSIZE 1024

int main(void)
{
    char hostname[BUFSIZE];
    hostname[BUFSIZE - 1] = '\0';
    gethostname(hostname, BUFSIZE - 1);
    printf("%s\n", hostname);
    return 0;
}
