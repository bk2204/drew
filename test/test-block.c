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

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_block_functbl_t *functbl = tbl;

	return print_test_results(functbl->test(NULL, ldr));
}

inline int test_speed_loop(const drew_block_functbl_t *functbl, uint8_t *buf,
		uint8_t *buf2, uint8_t *key, int keysz, int chunk, size_t nbytes)
{
	int i;
	drew_block_t ctx;

	functbl->init(&ctx, 0, NULL, NULL);
	functbl->setkey(&ctx, key, keysz, DREW_BLOCK_MODE_ENCRYPT);
	for (i = 0; !framework_sigflag && i < nbytes; i += chunk)
		functbl->encrypt(&ctx, buf2, buf);
	functbl->fini(&ctx, 0);

	return i;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 0;
	uint8_t *buf, *buf2, *key;
	void *fwdata;
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

	fwdata = framework_setup();

	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(functbl, buf, buf2, key, keysz, chunk, nbytes);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);

	print_speed_info(i, 1, &cstart, &cend);
	
	return 0;
}
