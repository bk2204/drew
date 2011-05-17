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
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/stream.h>

#define FILENAME "test/vectors-stream"

#define STUBS_API 1
#include "stubs.c"

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
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

struct testcase {
	char *id;
	char *algo;
	size_t klen;
	size_t nlen;
	uint8_t *key;
	uint8_t *nonce;
	size_t offstart;
	size_t offend;
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
		free(tc->nonce);
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
		return TEST_CORRUPT;
	if (strcmp(name, tc->algo))
		return TEST_NOT_FOR_US;
	ssize_t len = tc->offend - tc->offstart;
	if (len <= 0)
		return TEST_CORRUPT;
	if (!tc->pt || !tc->ct)
		return TEST_CORRUPT;
	uint8_t *buf = malloc(len);

	drew_stream_t ctx;
	ctx.functbl = tbl;
	ctx.functbl->init(&ctx, 0, tep->ldr, NULL);
	ctx.functbl->setkey(&ctx, tc->key, tc->klen, 0);
	ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
	for (size_t i = 0; i < tc->offstart/len; i++) {
		// Encrypt throwaway data to get to the proper offset.
		ctx.functbl->encrypt(&ctx, buf, buf, len);
	}
	size_t extra = tc->offstart % len;
	if (extra)
		ctx.functbl->encrypt(&ctx, buf, buf, extra);
	// Now at the proper offset.
	memset(buf, 0, len);
	ctx.functbl->encrypt(&ctx, buf, tc->pt, len);
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->ct, len)) {
		result = TEST_FAILED;
		goto out;
	}

	ctx.functbl->init(&ctx, 0, tep->ldr, NULL);
	ctx.functbl->setkey(&ctx, tc->key, tc->klen, 0);
	ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
	for (size_t i = 0; i < tc->offstart/len; i++) {
		// Encrypt throwaway data to get to the proper offset.
		ctx.functbl->decrypt(&ctx, buf, buf, len);
	}
	extra = tc->offstart % len;
	if (extra)
		ctx.functbl->decrypt(&ctx, buf, buf, extra);

	// Now at the proper offset.
	ctx.functbl->encrypt(&ctx, buf, tc->ct, len);
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->pt, len))
		result = TEST_FAILED;

out:
	free(buf);
	return result;
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
			break;
		case 'K':
			if (sscanf(item, "%zu", &tc->klen) != 1)
				return TEST_CORRUPT;
			break;
		case 'k':
			if (!tc->klen)
				return TEST_CORRUPT;
			if (process_bytes(tc->klen, &tc->key, item))
				return TEST_CORRUPT;
			break;
		case 'N':
			if (sscanf(item, "%zu", &tc->nlen) != 1)
				return TEST_CORRUPT;
			break;
		case 'n':
			if (!tc->nlen)
				return TEST_CORRUPT;
			if (process_bytes(tc->nlen, &tc->nonce, item))
				return TEST_CORRUPT;
			break;
		case 'S':
			if (sscanf(item, "%zu", &tc->offstart) != 1)
				return TEST_CORRUPT;
			break;
		case 'E':
			if (sscanf(item, "%zu", &tc->offend) != 1)
				return TEST_CORRUPT;
			break;
		case 'p':
			if (process_bytes(tc->offend - tc->offstart, &tc->pt, item))
				return TEST_CORRUPT;
			break;
		case 'c':
			if (process_bytes(tc->offend - tc->offstart, &tc->ct, item))
				return TEST_CORRUPT;
			break;
	}

	return TEST_OK;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 0, blksz;
	drew_stream_t ctx;
	uint8_t *buf, *buf2, *key;
	int (*encfunc)(drew_stream_t *, uint8_t *, const uint8_t *, size_t);
	struct timespec cstart, cend;
	
	ctx.functbl = tbl;

	keysz = ctx.functbl->info(DREW_STREAM_KEYSIZE, &keysz);
	blksz = ctx.functbl->info(DREW_STREAM_BLKSIZE, NULL);
	if (posix_memalign((void **)&buf, 16, chunk))
		return ENOMEM;

	if (posix_memalign((void **)&buf2, 16, chunk))
		return ENOMEM;

	encfunc = (chunk >= 16 && (chunk % blksz) == 0) ?
		ctx.functbl->encryptfast : ctx.functbl->encrypt;

	key = calloc(keysz, 1);
	if (!keysz)
		return ENOMEM;

	clock_gettime(USED_CLOCK, &cstart);
	ctx.functbl->init(&ctx, 0, NULL, NULL);
	ctx.functbl->setkey(&ctx, key, keysz, DREW_STREAM_MODE_ENCRYPT);
	for (i = 0; i < nchunks; i++)
		encfunc(&ctx, buf2, buf, chunk);
	clock_gettime(USED_CLOCK, &cend);
	ctx.functbl->fini(&ctx, 0);

	free(buf);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
