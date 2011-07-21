#include <stdint.h>
#include <stdlib.h>

#include <drew/mem.h>

#define NCHUNKS 4096

int main(void)
{
	uint32_t buf[50], *p[NCHUNKS];

	for (int i = 0, j = 5; i < 50; i++, j += i)
		buf[i] = j *= i;

	for (int i = 0; i < NCHUNKS; i++)
		p[i] = drew_mem_memdup(buf, sizeof(buf));
	for (int i = 0; i < (NCHUNKS-1); i++) {
		// idea from strfry.
		int j = rand();
		j = j % (NCHUNKS - i) + i;
		void *t = p[i];
		p[i] = p[j];
		p[j] = t;
	}
	for (int i = 0; i < NCHUNKS; i++)
		drew_mem_free(p[i]);
	return 0;
}
