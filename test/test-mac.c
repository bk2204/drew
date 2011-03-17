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

#include <plugin.h>
#include <mac.h>

int test_get_type(void)
{
	return DREW_TYPE_MAC;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return "MD5";
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_mac_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr));
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 32, resultsz = 512;
	uint8_t *buf, *key, *result;
	struct timespec cstart, cend;
	drew_mac_t ctx;
	drew_param_t param;

	if (!algo)
		algo = test_get_default_algo(ldr, name);

	param.name = "digest";
	param.next = NULL;
	param.param.string = algo;

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

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
