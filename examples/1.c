//usr/bin/gcc -Wno-format-security "$0" -o 1.out; exit
/* This example is to demonstrate how pwnscripts
 * can help out in making printf write exploits
 */
#include <stdio.h>
#include <string.h>
void win() { printf("\nflag{Goodjob}"); }
int main() {
	char s[64];
	memset(s, 0, 64);
	printf("%p\n", s);
	fgets(s, 50, stdin);
	printf(s);
	if (*(int*)(s+56) == 0x12345678) win();
}
