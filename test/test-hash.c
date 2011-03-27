/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different message digest
 * algorithms.  This implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/hash.h>

int test_get_type(void)
{
	return DREW_TYPE_HASH;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_hash_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr));
}

inline int test_speed_loop(drew_hash_t *ctx, uint8_t *buf,
		int chunk, int nchunks,
		int (*update)(drew_hash_t *, const uint8_t *, size_t))
{
	int i;

	for (i = 0; !framework_sigflag && i < nchunks; i++)
		update(ctx, buf, chunk);
	if (!framework_sigflag)
		ctx->functbl->final(ctx, buf, 0);
	ctx->functbl->fini(ctx, 0);

	return i;
}

const char *test_get_filename()
{
	return NULL;
}

void test_reset_data(void *p, int do_free)
{
}

void *test_create_data()
{
	return NULL;
}

int test_execute(void *data, const char *name, const void *tbl,
		const drew_loader_t *ldr)
{
	return TEST_NOT_IMPL;
}


int test_process_testcase(void *data, int type, const char *item)
{
	return TEST_OK;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, res, blksize;
	uint8_t *buf;
	struct timespec cstart, cend;
	drew_hash_t ctx;
	void *fwdata;
	int (*update)(drew_hash_t *, const uint8_t *, size_t);

	if ((res = posix_memalign((void **)&buf, DREW_HASH_ALIGNMENT, chunk)))
		return res;

	ctx.functbl = tbl;
	blksize = ctx.functbl->info(DREW_HASH_BLKSIZE, NULL);
	if (blksize <= 0)
		return -DREW_ERR_INVALID;

	fwdata = framework_setup();

	if ((res = ctx.functbl->init(&ctx, 0, NULL, NULL)) == -DREW_ERR_MORE_INFO) {
		size_t vals[] = {512, 384, 256, 224, 160, 128};
		for (int i = 0; i < DIM(vals); i++) {
			drew_param_t param;
			param.name = "digestSize";
			param.param.number = vals[i] / 8;
			param.next = NULL;
			if (!(res = ctx.functbl->init(&ctx, 0, NULL, &param)))
				break;
		}
	}
	if (res)
		return res;
	update = (!(chunk % blksize) && !(chunk % DREW_HASH_ALIGNMENT)) ? 
		ctx.functbl->updatefast : ctx.functbl->update;
	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(&ctx, buf, chunk, nchunks, update);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);

	print_speed_info(chunk, i, &cstart, &cend);
	
	return 0;
}
