#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnurable_func_strcat(char *payload)
{
    char broken_buffer[512];
    strcat(broken_buffer, payload);
}

void vulnurable_func_strcpy(char *payload)
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
    if(strncmp(argv[1], canary, 16) != 0)
    {
        printf("Argv[1] != Argv[2]\n");
        exit(1);
    }
    vulnurable_func_strcat(*(argv + 1));
    //vulnurable_func_strcpy(*(argv + 1));
    int c = a + b;
    printf("Exiting simple_buffer.c\n");
    return 0;
}
