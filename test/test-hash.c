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

#define FILENAME "test/vectors-hash"

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
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
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

struct testcase {
	char *id;
	char *algo;
	size_t nrepeats;
	size_t insize;
	uint8_t *in;
	size_t digestsize;
	uint8_t *digest;
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
		free(tc->in);
		free(tc->digest);
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
	size_t len = tc->digestsize;
	if (!tc->in || !tc->digest)
		return TEST_CORRUPT;
	uint8_t *buf = malloc(len);

	if (!tc->nrepeats)
		tc->nrepeats = 1;

	drew_param_t param;
	param.name = "digestSize";
	param.param.number = tc->digestsize;
	param.next = NULL;
	drew_hash_t ctx;
	ctx.functbl = tbl;
	ctx.functbl->init(&ctx, 0, tep->ldr, &param);
	for (size_t i = 0; i < tc->nrepeats; i++)
		ctx.functbl->update(&ctx, tc->in, tc->insize);
	ctx.functbl->final(&ctx, buf, 0);
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->digest, len))
		result = TEST_FAILED;

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
		case 'r':
			if (sscanf(item, "%zu", &tc->nrepeats) != 1)
				return TEST_CORRUPT;
			break;
		case 'C':
			if (sscanf(item, "%zu", &tc->digestsize) != 1)
				return TEST_CORRUPT;
			break;
		case 'p':
			tc->insize = strlen(item) / 2;
			if (process_bytes(tc->insize, &tc->in, item))
				return TEST_CORRUPT;
			break;
		case 'c':
			if (!tc->digestsize)
				tc->digestsize = strlen(item) / 2;
			if (process_bytes(tc->digestsize, &tc->digest, item))
				return TEST_CORRUPT;
			break;
	}

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
