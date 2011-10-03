/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
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
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/block.h>
#include <drew/mem.h>
#include <drew/mode.h>

#define FILENAME "test/vectors-mode"

#define STUBS_API 1
#include "stubs.c"

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

struct testcase {
	char *id;
	char *algo;
	char *mode;
	size_t klen;
	size_t nlen;
	uint8_t *key;
	uint8_t *nonce;
	size_t len;
	size_t feedbackBits;
	uint8_t *pt;
	uint8_t *ct;
	uint8_t *aad;
	size_t ctlen;
	size_t aadlen;
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
		free(tc->mode);
		free(tc->key);
		free(tc->nonce);
		free(tc->pt);
		free(tc->ct);
		free(tc->aad);
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

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	q->id = NULL;
	q->algo = strdup(p->algo);
	q->mode = strdup(p->mode);
	q->klen = p->klen;
	q->nlen = p->nlen;
	q->key = malloc(q->klen);
	memcpy(q->key, p->key, q->klen);
	q->nonce = malloc(q->nlen);
	memcpy(q->nonce, p->nonce, q->nlen);
	q->len = p->len;
	q->ctlen = p->ctlen;
	q->feedbackBits = p->feedbackBits;
	q->pt = malloc(q->len);
	memcpy(q->pt, p->pt, q->len);
	q->ct = malloc(q->ctlen);
	memcpy(q->ct, p->ct, q->ctlen);
	q->aadlen = p->aadlen;
	q->aad = drew_mem_memdup(p->aad, q->aadlen);

	return q;
}

char *test_get_id(void *data)
{
	struct testcase *tc = data;
	return strdup(tc->id);
}

static drew_block_t *new_block_cipher(struct test_external *tep,
		const char *name)
{
	drew_block_t *p;
	const void *tbl;
	int id = 0;

	if ((id = drew_loader_lookup_by_name(tep->ldr, name, 0, -1)) < 0)
		return NULL;
	if (drew_loader_get_type(tep->ldr, id) != DREW_TYPE_BLOCK)
		return NULL;
	if (drew_loader_get_functbl(tep->ldr, id, &tbl) < 0)
		return NULL;
	if (!(p = malloc(sizeof(*p))))
		return NULL;
	p->functbl = tbl;
	p->functbl->init(p, 0, tep->ldr, NULL);
	return p;
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
	// We may later make this default to ECB once it's implemented so that the
	// block cipher tests can be used with ECB.  Note that this will also
	// require the automatic determination of block size that is implemented in
	// test-block.c.
	if (!tc->mode)
		return TEST_CORRUPT;
	if (strcmp(name, tc->mode))
		return TEST_NOT_FOR_US;
	if (!tc->pt || !tc->ct)
		return TEST_CORRUPT;

	drew_mode_t ctx;
	drew_block_t *bctx = new_block_cipher(tep, tc->algo);
	drew_param_t param;
	int blksize = 0;
	bool use_fast = false;

	param.next = NULL;
	param.name = "feedbackBits";
	param.param.number = tc->feedbackBits;

	// If we don't have the block cipher available, fail gracefully.
	if (!bctx)
		return TEST_NOT_FOR_US;

	bctx->functbl->setkey(bctx, tc->key, tc->klen, 0);
	blksize = bctx->functbl->info(DREW_BLOCK_BLKSIZE, 0);

	if (((tc->feedbackBits / 8) == blksize) && !(tc->len % blksize) &&
			!tc->aadlen && tc->ctlen == tc->len)
		use_fast = true;

	uint8_t *buf = malloc(tc->ctlen), *buf2 = malloc(tc->ctlen);
	ctx.functbl = tbl;
	ctx.functbl->init(&ctx, 0, tep->ldr, tc->feedbackBits ? &param : NULL);
	ctx.functbl->setblock(&ctx, bctx);
	ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
	if (tc->aadlen)
		ctx.functbl->setdata(&ctx, tc->aad, tc->aadlen);
	ctx.functbl->encrypt(&ctx, buf, tc->pt, tc->len);
	if (tc->len != tc->ctlen)
		ctx.functbl->encryptfinal(&ctx, buf+tc->len, tc->ctlen-tc->len, NULL,
				0);
	if (use_fast) {
		ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
		ctx.functbl->encryptfast(&ctx, buf2, tc->pt, tc->len);
	}
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->ct, tc->ctlen)) {
		result = TEST_FAILED;
		goto out;
	}
	if (use_fast && memcmp(buf2, tc->ct, tc->ctlen)) {
		result = TEST_FAILED;
		goto out;
	}

	ctx.functbl->init(&ctx, 0, tep->ldr, tc->feedbackBits ? &param : NULL);
	ctx.functbl->setblock(&ctx, bctx);
	ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
	if (tc->aadlen)
		ctx.functbl->setdata(&ctx, tc->aad, tc->aadlen);
	ctx.functbl->decrypt(&ctx, buf, tc->ct, tc->len);
	if (tc->len != tc->ctlen)
		if (ctx.functbl->decryptfinal(&ctx, NULL, 0, tc->ct+tc->len,
					tc->ctlen-tc->len) < 0)
			result = TEST_FAILED;
	if (use_fast) {
		ctx.functbl->setiv(&ctx, tc->nonce, tc->nlen);
		ctx.functbl->decryptfast(&ctx, buf2, tc->ct, tc->len);
	}
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->pt, tc->len))
		result = TEST_FAILED;
	if (use_fast && memcmp(buf2, tc->pt, tc->len))
		result = TEST_FAILED;

out:
	free(buf);
	free(buf2);
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
		case 'm':
			free(tc->mode);
			tc->mode = strdup(item);
			break;
		case 'F':
			if (sscanf(item, "%zu", &tc->feedbackBits) != 1)
				return TEST_CORRUPT;
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
		case 'p':
			tc->len = strlen(item) / 2;
			if (process_bytes(tc->len, &tc->pt, item))
				return TEST_CORRUPT;
			break;
		case 'c':
			tc->ctlen = strlen(item) / 2;
			if (process_bytes(tc->ctlen, &tc->ct, item))
				return TEST_CORRUPT;
			break;
		case 'd':
			tc->aadlen = strlen(item) / 2;
			if (process_bytes(tc->aadlen, &tc->aad, item))
				return TEST_CORRUPT;
			break;
	}

	return TEST_OK;
}

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
