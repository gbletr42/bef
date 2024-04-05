#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#define ITER	1024

/* Same as error.c, but with random errors instead. Not used in testing due to
 * nondeterminism, but useful when experimenting like a good monkey.
 */
int main() {
	int i = 0;
	char in[4096];
	char noise[4096];

	while(fread(in, 4096, 1, stdin) != 0) {
		/* Corrupt one byte */
		getrandom(&i, sizeof(i), 0);
		if(i % ITER == 0) {
			getrandom(&i, sizeof(i), 0);
			in[i % 4096] = '\0';
		}
		/* Add random noise */
		getrandom(&i, sizeof(i), 0);
		if(i % ITER == 0) {
			getrandom(&i, sizeof(i), 0);
			getrandom(noise, sizeof(noise), 0);
			fwrite(noise, i % 4096, 1, stdout);
		}
		/* Lose output (at least one byte worth) */
		getrandom(&i, sizeof(i), 0);
		if(i % ITER != 0) {
			fwrite(in, 4096, 1, stdout);
		} else {
			getrandom(&i, sizeof(i), 0);
			fwrite(in, i % 4095, 1, stdout);
		}
	}
}
