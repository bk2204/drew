/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a generic test framework.  This implementation requires
 * ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <plugin.h>

double sec_from_timespec(const struct timespec *ts)
{
	return ts->tv_sec + (ts->tv_nsec / 1000000000.0);
}

void print_speed_info(int chunk, int nchunks, const struct timespec *cstart,
		const struct timespec *cend)
{
	double start, end, rate, diff;

	start = sec_from_timespec(cstart);
	end = sec_from_timespec(cend);
	diff = end - start;
	rate = chunk * ((double)nchunks) / diff;
	rate /= 1048576;

	printf("%d bytes in %0.3fs (%0.3f MiB/s)\n", (nchunks*chunk), diff, rate);
}

int main(int argc, char **argv)
{
	int error = 0;
	int i;
	int mode = 0;
	int nplugins = 0;
	int opt = 0;
	int type = 0;
	int chunk = 0;
	int nchunks = 0;
	int retval = 0;
	int success_only = 0;
	const char *algo = NULL;
	const char *only = NULL;
	drew_loader_t *ldr = NULL;

	drew_loader_new(&ldr);

	while ((opt = getopt(argc, argv, "stifa:c:n:o:")) != -1) {
		switch (opt) {
			case 's':
				mode = MODE_SPEED;
				break;
			case 't':
				mode = MODE_TEST;
				break;
			case 'i':
				mode = MODE_TEST_INTERNAL;
				break;
			case 'f':
				success_only = 1;
				break;
			case 'a':
				algo = optarg;
				break;
			case 'c':
				chunk = atoi(optarg);
				break;
			case 'n':
				nchunks = atoi(optarg);
				break;
			case 'o':
				only = optarg;
				break;
		}
	}

	if (!mode)
		mode = MODE_SPEED;
	if (chunk <= 0)
		chunk = CHUNK;
	if (nchunks <= 0)
		nchunks = NCHUNKS;

	if ((retval = drew_loader_load_plugin(ldr, NULL, NULL))) {
		printf("<internal>: failed to load (error %d (%s))\n", -retval,
				strerror(-retval));
		error++;
	}

	for (; optind < argc; optind++) {
		int id;

		id = drew_loader_load_plugin(ldr, argv[optind], "./plugins");
		if (id < 0) {
			printf("%s: failed to load (error %d (%s))\n", argv[optind], -id,
					strerror(-id));
			error++;
			continue;
		}
	}

	if (algo)
		printf("# Using algorithm %s for tests.\n", algo);

	nplugins = drew_loader_get_nplugins(ldr, -1);
	type = test_get_type();

	for (i = 0; i < nplugins; i++) {
		const void *functbl;
		const char *name;
		int result = 0;

		if (drew_loader_get_type(ldr, i) != type)
			continue;

		drew_loader_get_functbl(ldr, i, &functbl);
		drew_loader_get_algo_name(ldr, i, &name);

		if (only && strcmp(only, name))
			continue;

		printf("%-11s: ", name);

		switch (mode) {
			case MODE_SPEED:
				test_speed(ldr, name, algo, functbl, chunk, nchunks);
				break;
			case MODE_TEST:
			case MODE_TEST_INTERNAL:
				result = test_internal(ldr, name, functbl);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
			default:
				break;
		}
	}
	drew_loader_free(&ldr);

	if (error && !(error & 0xff))
		error++;
	return error;
}
