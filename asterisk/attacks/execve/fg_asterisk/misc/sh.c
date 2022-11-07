#include <unistd.h>
#include <stdio.h>

int main(void)
{
    //char *argv[] = { "A", 0 };
    //execve(argv[0], &argv[0], NULL);
    //execve("/bin/sh", &argv[0], NULL);
    execve("/bin/sh", NULL, NULL);
    fprintf(stderr, "Oops!\n");
    return -1;
}
