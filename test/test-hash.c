/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different message digest
 * algorithms.  This implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <plugin.h>

struct plugin_functbl {
	int (*info)(int, void *);
	void (*init)(void **);
	void (*update)(void *, const uint8_t *, size_t);
	void (*pad)(void *);
	void (*final)(void *, uint8_t *);
	void (*transform)(void *, void *, const uint8_t *);
	int (*test)(void *);
};

struct plugin_info {
	const char *name;
	struct plugin_functbl *tbl;
};

#define DIM(x) (sizeof(x)/sizeof(x[0]))

struct context {
	void *ctx;
};

#define MODE_SPEED			1
#define MODE_TEST			2
#define MODE_TEST_INTERNAL	3

#define CHUNK 8192
#define NCHUNKS 40960

double sec_from_timespec(const struct timespec *ts)
{
	return ts->tv_sec + (ts->tv_nsec / 1000000000.0);
}

int internal_test(const char *name, const struct plugin_functbl *functbl)
{
	int result;
	
	result = functbl->test(NULL);
	printf("self-test %s (result code %d)\n", result ? "failed" : "ok", result);
	return 0;
}

int speed_test(const char *name, const struct plugin_functbl *functbl)
{
	int i;
	void *ctx;
	uint8_t *buf;
	struct timespec cstart, cend;
	double start, end, diff, rate;

	buf = calloc(CHUNK, 1);
	if (!buf)
		return ENOMEM;

	clock_gettime(CLOCK_REALTIME, &cstart);
	functbl->init(&ctx);
	for (i = 0; i < NCHUNKS; i++)
		functbl->update(ctx, buf, CHUNK);
	functbl->final(ctx, buf);
	clock_gettime(CLOCK_REALTIME, &cend);

	free(buf);

	start = sec_from_timespec(&cstart);
	end = sec_from_timespec(&cend);
	diff = end - start;
	rate = CHUNK * ((double)NCHUNKS) / diff;
	rate /= 1048576;

	printf("%d bytes in %0.3fs (%0.3f MiB/s)\n", (NCHUNKS*CHUNK), diff, rate);
	
	return 0;
}

int main(int argc, char **argv)
{
	int error = 0;
	int i;
	int mode = 0;
	int nplugins = 0;
	drew_loader_t *ldr = NULL;

	drew_loader_new(&ldr);

	for (i = 1; i < argc; i++) {
		int id;

		if (!mode) {
			if (!strcmp(argv[i], "-s"))
				mode = MODE_SPEED;
			else if (!strcmp(argv[i], "-t"))
				mode = MODE_TEST;
			else if (!strcmp(argv[i], "-i"))
				mode = MODE_TEST_INTERNAL;
			else
				mode = MODE_SPEED;
			continue;
		}

		id = drew_loader_load_plugin(ldr, argv[i], "./plugins");
		if (id < 0) {
			printf("%s: failed to load (error %d (%s))\n", argv[i], -id,
					strerror(-id));
			error++;
			continue;
		}
	}

	nplugins = drew_loader_get_nplugins(ldr, -1);

	for (i = 0; i < nplugins; i++) {
		const void *functbl;
		struct plugin_functbl *tbl;
		const char *name;

		if (drew_loader_get_type(ldr, i) != DREW_TYPE_HASH)
			continue;

		drew_loader_get_functbl(ldr, i, &functbl);
		drew_loader_get_algo_name(ldr, i, &name);
		printf("%s: ", name);
		tbl = (struct plugin_functbl *)functbl;

		switch (mode) {
			case MODE_SPEED:
				speed_test(name, tbl);
				break;
			case MODE_TEST:
			case MODE_TEST_INTERNAL:
				internal_test(name, tbl);
			default:
				break;
		}
	}
	drew_loader_free(&ldr);

	return error;
}
