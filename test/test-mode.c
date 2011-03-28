/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different block cipher modes.
 * This implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/block.h>
#include <drew/mode.h>

int test_get_type(void)
{
	return DREW_TYPE_MODE;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return "AES128";
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_mode_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

#include "stubs.c"

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 0, blksz;
	drew_block_t bctx;
	drew_mode_t mctx;
	uint8_t *buf, *buf2, *key;
	struct timespec cstart, cend;
	const drew_block_functbl_t *ftbl;
	int (*encrypt)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int id;

	if (!algo)
		algo = test_get_default_algo(ldr, name);

	id = drew_loader_lookup_by_name(ldr, algo, 0, -1);
	if (id < 0)
		return ENOTSUP;

	const void *p;
	drew_loader_get_functbl(ldr, id, &p);
	ftbl = p;

	blksz = ftbl->info(DREW_BLOCK_BLKSIZE, NULL);
	keysz = ftbl->info(DREW_BLOCK_KEYSIZE, &keysz);
	if (posix_memalign((void **)&buf, DREW_MODE_ALIGNMENT, chunk))
		return ENOMEM;

	buf2 = calloc(blksz, 1);
	if (!buf2)
		return ENOMEM;

	key = calloc(keysz, 1);
	if (!keysz)
		return ENOMEM;

	mctx.functbl = tbl;
	clock_gettime(USED_CLOCK, &cstart);
	ftbl->init(&bctx, 0, NULL, NULL);
	ftbl->setkey(&bctx, key, keysz, 0);
	mctx.functbl->init(&mctx, 0, ldr, NULL);
	mctx.functbl->setiv(&mctx, buf2, blksz);
	mctx.functbl->setblock(&mctx, &bctx);
	encrypt = (chunk & 15) ? mctx.functbl->encrypt : mctx.functbl->encryptfast;
	for (i = 0; i < nchunks; i++)
		encrypt(&mctx, buf, buf, chunk);
	clock_gettime(USED_CLOCK, &cend);

	free(buf);
	free(buf2);
	free(key);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
