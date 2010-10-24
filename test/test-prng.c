/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different PRNGs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <plugin.h>
#include <prng.h>

int test_get_type(void)
{
	return DREW_TYPE_PRNG;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	int result;
	const drew_prng_functbl_t *functbl = tbl;
	
	result = functbl->test(NULL, ldr);
	printf("self-test %s (result code %d)\n", result ? "failed" : "ok", result);
	return result;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, blksz = 0;
	void *ctx;
	uint8_t *buf, *blk;
	struct timespec cstart, cend;
	const drew_prng_functbl_t *functbl = tbl;

	blksz = functbl->info(DREW_PRNG_BLKSIZE, NULL);
	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	blk = malloc(blksz);
	if (!blk)
		return ENOMEM;

	clock_gettime(USED_CLOCK, &cstart);
	functbl->init(&ctx, NULL, 0, NULL, NULL);
	functbl->seed(ctx, blk, blksz, blksz);
	for (i = 0; i < nchunks; i++)
		functbl->bytes(ctx, buf, chunk);
	clock_gettime(USED_CLOCK, &cend);
	functbl->fini(&ctx, 0);

	free(buf);
	free(blk);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
