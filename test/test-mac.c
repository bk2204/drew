/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different MACs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/mac.h>
#include <drew/hash.h>
#include <drew/block.h>

int test_get_type(void)
{
	return DREW_TYPE_MAC;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return "MD5";
}

const char *test_get_default_block_algo(drew_loader_t *ldr, const char *name)
{
	return "AES128";
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_mac_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

#define STUBS_EXTERNAL 1
#define STUBS_API 1
#include "stubs.c"

struct generic {
	void *ctx;
	const void *functbl;
	void *priv;
};

static int make_new_ctx(const drew_loader_t *ldr, const char *name, void *ctx,
		int type)
{
	int id = -1, res = 0;
	struct generic *g = ctx;

	if ((id = res = drew_loader_lookup_by_name(ldr, name, 0, -1)) < 0)
		return res;

	if (drew_loader_get_type(ldr, id) != type)
		return -DREW_ERR_INVALID;

	if ((res = drew_loader_get_functbl(ldr, id, &g->functbl)) < 0)
		return res;

	return 0;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 32, resultsz = 512, res = 0;
	uint8_t *buf, *key, *result;
	struct timespec cstart, cend;
	drew_mac_t ctx;
	drew_param_t param, bparam;
	drew_hash_t hash;
	drew_block_t block;
	const char *balgo = NULL;

	if (!algo)
		algo = test_get_default_algo(ldr, name);

	if (!balgo)
		balgo = test_get_default_block_algo(ldr, name);

	if ((res = make_new_ctx(ldr, algo, &hash, DREW_TYPE_HASH)) < 0)
		return res;

	if ((res = make_new_ctx(ldr, balgo, &block, DREW_TYPE_BLOCK)) < 0)
		return res;

	param.name = "digest";
	param.next = &bparam;
	param.param.value = &hash;

	bparam.name = "cipher";
	bparam.next = NULL;
	bparam.param.value = &block;

	hash.functbl->init(&hash, 0, ldr, NULL);
	block.functbl->init(&block, 0, ldr, NULL);

	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	key = calloc(keysz, 1);
	if (!key)
		return ENOMEM;

	result = calloc(resultsz, 1);
	if (!result)
		return ENOMEM;

	ctx.functbl = tbl;

	clock_gettime(USED_CLOCK, &cstart);
	ctx.functbl->init(&ctx, 0, ldr, &param);
	ctx.functbl->setkey(&ctx, key, keysz);
	for (i = 0; i < nchunks; i++)
		ctx.functbl->update(&ctx, buf, chunk);
	ctx.functbl->final(&ctx, result, 0);
	clock_gettime(USED_CLOCK, &cend);
	ctx.functbl->fini(&ctx, 0);

	free(buf);
	free(key);
	free(result);

	hash.functbl->fini(&hash, 0);
	block.functbl->fini(&block, 0);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
