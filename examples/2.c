//usr/bin/gcc -Wno-format-security -fno-stack-protector -no-pie "$0" -o 2.out; exit
/* This example is to show how printf can be used
 * in conjuction with the `libc_db` class to
 * identify a remote libc version
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){
    char s[64];
    fgets(s, 64, stdin);
    printf(s);
    if (!strcmp(s, "libc6_2.27-3ubuntu1_amd64\n"))
        puts("flag{congrats}");
    else
        puts("failure");
}
