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
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/block.h>

#define FILENAME "test/vectors-block"

#define STUBS_API 1
#include "stubs.c"

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

	return print_test_results(functbl->test(NULL, ldr), NULL);
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

struct testcase {
	char *id;
	char *algo;
	size_t klen;
	uint8_t *key;
	size_t blksize;
	uint8_t *pt;
	uint8_t *ct;
};

const char *test_get_filename()
{
	return FILENAME;
}

void test_reset_data(void *p, int flags)
{
	struct testcase *tc = p;
	if (flags & TEST_RESET_PARTIAL) {
		free(tc->id);
		tc->id = NULL;
	}
	if (flags & TEST_RESET_FREE) {
		free(tc->id);
		free(tc->algo);
		free(tc->key);
		free(tc->pt);
		free(tc->ct);
		memset(p, 0, sizeof(struct testcase));
	}
	if (flags & TEST_RESET_ZERO)
		memset(p, 0, sizeof(struct testcase));
}

void *test_create_data()
{
	void *p = malloc(sizeof(struct testcase));
	test_reset_data(p, TEST_RESET_ZERO);
	return p;
}

char *test_get_id(void *data)
{
	struct testcase *tc = data;
	return strdup(tc->id);
}

int test_execute(void *data, const char *name, const void *tbl,
		struct test_external *tep)
{
	int result = 0;
	struct testcase *tc = data;
	// If the test isn't for us or is corrupt, we succeed since it isn't
	// relevant for our case.
	if (!tc->algo)
		return TEST_CORRUPT | 1;
	if (strcmp(name, tc->algo))
		return TEST_NOT_FOR_US;
	size_t len = tc->blksize;
	if (!tc->pt || !tc->ct)
		return TEST_CORRUPT | 2;
	uint8_t *buf = malloc(len);

	drew_block_t ctx;
	ctx.functbl = tbl;
	ctx.functbl->init(&ctx, 0, tep->ldr, NULL);
	if (ctx.functbl->setkey(&ctx, tc->key, tc->klen, 0) == -DREW_ERR_NOT_IMPL) {
		result = TEST_NOT_FOR_US;
		goto out;
	}
	ctx.functbl->encrypt(&ctx, buf, tc->pt);
	if (memcmp(buf, tc->ct, len)) {
		result = TEST_FAILED | 'e';
		goto out;
	}
	ctx.functbl->fini(&ctx, 0);

	ctx.functbl->init(&ctx, 0, tep->ldr, NULL);
	ctx.functbl->setkey(&ctx, tc->key, tc->klen, 0);
	ctx.functbl->decrypt(&ctx, buf, tc->ct);
	if (memcmp(buf, tc->pt, len))
		result = TEST_FAILED | 'd';

out:
	ctx.functbl->fini(&ctx, 0);
	free(buf);
	return result;
}

// We return 0 if we don't know.  Maybe the algorithm hasn't been loaded yet.
static size_t get_block_size(struct test_external *tep, struct testcase *tc)
{
	int res = 0;
	drew_block_t ctx;
	const void *tbl;
	// We're looking for the block size here, so any implementation will
	// do, since every implementation of the same algorithm should have
	// the same block size.
	if ((res = drew_loader_lookup_by_name(tep->ldr, tc->algo, 0, -1)) < 0)
		return 0;
	if (drew_loader_get_type(tep->ldr, res) != test_get_type())
		return 0;
	if (drew_loader_get_functbl(tep->ldr, res, &tbl) < 0)
		return 0;
	ctx.functbl = tbl;
	if ((res = ctx.functbl->info(DREW_BLOCK_BLKSIZE, 0)) < 0)
		return 0;
	return res;
}

int test_process_testcase(void *data, int type, const char *item,
		struct test_external *tep)
{
	struct testcase *tc = data;

	switch (type) {
		case 'T':
			if (!tc->id)
				tc->id = strdup(item);
			else if (strcmp(tc->id, item))
				return TEST_EXECUTE;
			break;
		case 'a':
			free(tc->algo);
			tc->algo = strdup(item);
			tc->blksize = get_block_size(tep, tc);
			break;
		case 'K':
			if (sscanf(item, "%zu", &tc->klen) != 1)
				return TEST_CORRUPT | 'K';
			break;
		case 'k':
			if (!tc->klen)
				return TEST_CORRUPT | 3;
			if (process_bytes(tc->klen, &tc->key, item))
				return TEST_CORRUPT | 'k';
			break;
		case 'p':
			if (!tc->blksize)
				tc->blksize = strlen(item) / 2;
			if (process_bytes(tc->blksize, &tc->pt, item))
				return TEST_CORRUPT | 'p';
			break;
		case 'c':
			if (!tc->blksize)
				tc->blksize = strlen(item) / 2;
			if (process_bytes(tc->blksize, &tc->ct, item))
				return TEST_CORRUPT | 'c';
			break;
	}

	return TEST_OK;
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
