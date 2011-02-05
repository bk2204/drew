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

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_prng_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr));
}

inline int test_speed_loop(const drew_prng_functbl_t *functbl, uint8_t *buf,
		uint8_t *blk, int blksz, int chunk, int nchunks)
{
	int i;
	void *ctx;

	functbl->init(&ctx, NULL, 0, NULL, NULL);
	functbl->seed(ctx, blk, blksz, blksz);
	for (i = 0; !framework_sigflag && i < nchunks; i++)
		functbl->bytes(ctx, buf, chunk);
	functbl->fini(&ctx, 0);

	return i;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, blksz = 0;
	uint8_t *buf, *blk;
	struct timespec cstart, cend;
	const drew_prng_functbl_t *functbl = tbl;
	void *fwdata;

	blksz = functbl->info(DREW_PRNG_BLKSIZE, NULL);
	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	blk = malloc(blksz);
	if (!blk)
		return ENOMEM;

	fwdata = framework_setup();

	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(functbl, buf, blk, blksz, chunk, nchunks);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);
	free(blk);

	print_speed_info(chunk, i, &cstart, &cend);
	
	return 0;
}
