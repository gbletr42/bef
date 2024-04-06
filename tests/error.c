#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#define ITER	256

int main() {
	int i = 0;
	char in[4096];
	char noise[4096];

	while(fread(in, 4096, 1, stdin) != 0) {
		/* Corrupt one byte */
		if(i % ITER == 0)
			in[78] = '\0';
		/* Add random noise */
		if(i % ITER == ITER / 2) {
			getrandom(noise, sizeof(noise), 0);
			fwrite(noise, 4096, 1, stdout);
		}
		/* Lose output */
		if(i % ITER != ITER - 1)
			fwrite(in, 4096, 1, stdout);
		i++;
	}
}
