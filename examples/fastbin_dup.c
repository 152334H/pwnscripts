//usr/bin/gcc "$0" -o f.out; exit
#include <stdio.h>
#include <stdlib.h>
int main() {
	int *a = malloc(8), *b = malloc(8), *c = malloc(8);
	free(a); free(b); free(a);
	malloc(8); malloc(8); malloc(8);
}
