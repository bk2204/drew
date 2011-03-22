/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different stream ciphers.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/stream.h>

int test_get_type(void)
{
	return DREW_TYPE_STREAM;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_stream_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr));
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 0;
	drew_stream_t ctx;
	uint8_t *buf, *buf2, *key;
	struct timespec cstart, cend;
	
	ctx.functbl = tbl;

	keysz = ctx.functbl->info(DREW_STREAM_KEYSIZE, &keysz);
	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	buf2 = calloc(chunk, 1);
	if (!buf2)
		return ENOMEM;

	key = calloc(keysz, 1);
	if (!keysz)
		return ENOMEM;

	clock_gettime(USED_CLOCK, &cstart);
	ctx.functbl->init(&ctx, 0, NULL, NULL);
	ctx.functbl->setkey(&ctx, key, keysz, DREW_STREAM_MODE_ENCRYPT);
	for (i = 0; i < nchunks; i++)
		ctx.functbl->encrypt(&ctx, buf2, buf, chunk);
	clock_gettime(USED_CLOCK, &cend);
	ctx.functbl->fini(&ctx, 0);

	free(buf);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
