#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnurable_func(char *payload)
{
    char broken_buffer[512];
    strcpy(broken_buffer, payload);
}

int main(int argc, char **argv)
{
    int a = 10;
    int b = 20;
    if(argc < 3)
    {
        printf("Not enough arguments to %s!\n", __FILE__);
        exit(1);
    }
    char *canary = argv[2];
    if(strncmp(argv[1], canary, 17) != 0)
    {
        exit(1);
    }
    vulnurable_func(*(argv + 1));
    int c = a + b;
    printf("Exiting simple_buffer.c\n");
    return 0;
}
