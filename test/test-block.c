/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different block ciphers.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <plugin.h>
#include <block.h>

int test_get_type(void)
{
	return DREW_TYPE_BLOCK;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	int result;
	const drew_block_functbl_t *functbl = tbl;
	
	result = functbl->test(NULL);
	printf("self-test %s (result code %d)\n", result ? "failed" : "ok", result);
	return 0;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 0;
	void *ctx;
	uint8_t *buf, *buf2, *key;
	struct timespec cstart, cend;
	const drew_block_functbl_t *functbl = tbl;
	const size_t nbytes = chunk * nchunks;

	chunk = functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	keysz = functbl->info(DREW_BLOCK_KEYSIZE, &keysz);
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
	functbl->init(&ctx, NULL, NULL);
	functbl->setkey(ctx, key, keysz);
	for (i = 0; i < nbytes; i += chunk)
		functbl->encrypt(ctx, buf2, buf);
	clock_gettime(USED_CLOCK, &cend);
	functbl->fini(&ctx);

	free(buf);

	print_speed_info(nbytes, 1, &cstart, &cend);
	
	return 0;
}
