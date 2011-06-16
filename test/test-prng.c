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

#include <drew/plugin.h>
#include <drew/prng.h>

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
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

inline int test_speed_loop(drew_prng_t *ctx, uint8_t *buf,
		uint8_t *blk, int blksz, int chunk, int nchunks,
		const drew_loader_t *ldr)
{
	int i;

	ctx->functbl->init(ctx, 0, ldr, NULL);
	ctx->functbl->seed(ctx, blk, blksz, blksz);
	for (i = 0; !framework_sigflag && i < nchunks; i++)
		ctx->functbl->bytes(ctx, buf, chunk);
	ctx->functbl->fini(ctx, 0);

	return i;
}

int test_external(const drew_loader_t *ldr, const char *name, const void *tbl,
		const char *filename, struct test_external *tes)
{

	return print_test_results(-DREW_ERR_NOT_IMPL, NULL);
}

int test_external_parse(const drew_loader_t *ldr, const char *filename,
		struct test_external *tes)
{
	return 0;
}

#define STUBS_API 1
#include "stubs.c"

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, blksz = 0;
	uint8_t *buf, *blk;
	struct timespec cstart, cend;
	drew_prng_t ctx;
	void *fwdata;

	ctx.functbl = tbl;

	blksz = ctx.functbl->info(DREW_PRNG_BLKSIZE, NULL);
	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	blk = malloc(blksz);
	if (!blk)
		return ENOMEM;

	fwdata = framework_setup();

	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(&ctx, buf, blk, blksz, chunk, nchunks, ldr);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);
	free(blk);

	print_speed_info(chunk, i, &cstart, &cend);
	
	return 0;
}
