//usr/bin/gcc -Wno-format-security -fstack-protector-all -pie "$0" -Wl,-z,now -o 3.out; exit
/* There are probably many ways to exploit this one,
 * but the core idea is that you leak the cookie+PIE,
 * and use that to return to win().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void win(){ puts("flag{NiceOne}"); }
int main(){
    char s[64];
    fgets(s, 64, stdin);
    printf(s);
    fgets(s, 100, stdin);
}
