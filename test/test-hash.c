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
#include <time.h>

#include <plugin.h>
#include <hash.h>

int test_get_type(void)
{
	return DREW_TYPE_HASH;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	int result;
	const drew_hash_functbl_t *functbl = tbl;
	
	result = functbl->test(NULL);
	printf("self-test %s (result code %d)\n", result ? "failed" : "ok", result);
	return 0;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i;
	void *ctx;
	uint8_t *buf;
	struct timespec cstart, cend;
	const drew_hash_functbl_t *functbl = tbl;

	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	clock_gettime(USED_CLOCK, &cstart);
	functbl->init(&ctx, NULL, NULL);
	for (i = 0; i < nchunks; i++)
		functbl->update(ctx, buf, chunk);
	functbl->final(ctx, buf);
	clock_gettime(USED_CLOCK, &cend);

	free(buf);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
