#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    int a = 10;
    int b = 20;
    char buffer[128];
    if(argc < 2)
    {
        printf("Not enough arguments to %s!\n", __FILE__);
        exit(1);
    }

    strcpy(buffer, *(argv + 1));
    int c = a + b;
    printf("Buffer is currently: %s\n", buffer);
    printf("Exiting simple_buffer.c\n");
    return 0;
}
