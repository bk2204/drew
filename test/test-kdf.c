/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different KDFs and PRFs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/block.h>
#include <drew/kdf.h>
#include <drew/hash.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#define FILENAME "test/vectors-kdf"

static int make_new_ctx(const drew_loader_t *ldr, const char *name, void *ctx,
		int type);

int test_get_type(void)
{
	return DREW_TYPE_KDF;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return "SHA-1";
}

const char *test_get_default_block_algo(drew_loader_t *ldr, const char *name)
{
	return "AES128";
}

const char *test_get_default_kdf_algo(void)
{
	return "HMAC-KDF";
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_kdf_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

struct testcase {
	char *id;
	char *algo;
	char *kdf;
	char *prf;
	size_t klen;
	uint8_t *key;
	size_t count;
	size_t slen;
	uint8_t *salt;
	size_t len;
	size_t kdflen;
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
		drew_mem_free(tc->id);
		tc->id = NULL;
	}
	if (flags & TEST_RESET_FREE) {
		drew_mem_free(tc->id);
		drew_mem_free(tc->algo);
		drew_mem_free(tc->kdf);
		drew_mem_free(tc->prf);
		drew_mem_free(tc->key);
		drew_mem_free(tc->salt);
		drew_mem_free(tc->pt);
		drew_mem_free(tc->ct);
		memset(p, 0, sizeof(struct testcase));
	}
	if (flags & TEST_RESET_ZERO)
		memset(p, 0, sizeof(struct testcase));
}

void *test_create_data()
{
	void *p = drew_mem_malloc(sizeof(struct testcase));
	test_reset_data(p, TEST_RESET_ZERO);
	return p;
}

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	memcpy(q, p, sizeof(*q));
	q->id = NULL;
	q->algo = strdup(p->algo);
	q->kdf = strdup(p->kdf);
	if (p->prf)
		q->prf = strdup(p->prf);
	q->key = drew_mem_memdup(p->key, q->klen);
	q->pt = drew_mem_memdup(p->pt, q->len);
	q->ct = drew_mem_memdup(p->ct, q->kdflen);
	q->salt = drew_mem_memdup(p->salt, q->slen);

	return q;
}

char *test_get_id(void *data)
{
	struct testcase *tc = data;
	return strdup(tc->id);
}

int test_execute(void *data, const char *name, const void *tbl,
		struct test_external *tep)
{
	int res = 0;
	struct testcase *tc = data;
	// If the test isn't for us or is corrupt, we succeed since it isn't
	// relevant for our case.
	if (!tc->algo)
		return TEST_CORRUPT;
	if (!tc->kdf)
		return TEST_CORRUPT;
	if (strcmp(name, tc->kdf))
		return TEST_NOT_FOR_US;
	if (!tc->pt || !tc->ct)
		return TEST_CORRUPT;

	drew_kdf_t ctx, *prf = NULL;
	drew_param_t param, param2;
	drew_hash_t hash;
	drew_block_t block;

	memset(&param, 0, sizeof(param));
	memset(&hash, 0, sizeof(hash));
	memset(&block, 0, sizeof(block));

	if (!(res = make_new_ctx(tep->ldr, tc->algo, &hash, DREW_TYPE_HASH))) {
		param.name = "digest";
		param.next = NULL;
		param.param.value = &hash;
		hash.functbl->init(&hash, 0, tep->ldr, NULL);
	}
	else if (!(res = make_new_ctx(tep->ldr, tc->algo, &block, DREW_TYPE_BLOCK))) {
		param.name = "cipher";
		param.next = NULL;
		param.param.value = &block;
		block.functbl->init(&block, 0, tep->ldr, NULL);
	}
	else
		return TEST_NOT_FOR_US;

	if (tc->prf && strlen(tc->prf)) {
		prf = drew_mem_malloc(sizeof(*prf));
		if ((res = make_new_ctx(tep->ldr, tc->prf, prf, DREW_TYPE_KDF))) {
			drew_mem_free(prf);
			return TEST_NOT_FOR_US;
		}
		prf->functbl->init(prf, 0, tep->ldr, &param);
		param2.name = "prf";
		param2.next = NULL;
		param2.param.value = prf;
		param.next = &param2;
	}

	uint8_t *buf = drew_mem_malloc(tc->kdflen);
	ctx.functbl = tbl;
	if (ctx.functbl->init(&ctx, 0, tep->ldr, &param))
		return TEST_FAILED;
	if (tc->klen)
		ctx.functbl->setkey(&ctx, tc->key, tc->klen);
	if (tc->slen)
		ctx.functbl->setsalt(&ctx, tc->salt, tc->slen);
	if (tc->count)
		ctx.functbl->setcount(&ctx, tc->count);
	ctx.functbl->generate(&ctx, buf, tc->kdflen, tc->pt, tc->len);
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->ct, tc->kdflen))
		res = TEST_FAILED;

	if (prf) {
		prf->functbl->fini(prf, 0);
		drew_mem_free(prf);
	}
	if (hash.ctx)
		hash.functbl->fini(&hash, 0);
	if (block.ctx)
		block.functbl->fini(&block, 0);

	drew_mem_free(buf);
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
		case 'g':
			drew_mem_free(tc->prf);
			tc->prf = strdup(item);
			break;
		case 'a':
			drew_mem_free(tc->algo);
			tc->algo = strdup(item);
			break;
		case 'm':
			drew_mem_free(tc->kdf);
			tc->kdf = strdup(item);
			break;
		case 'R':
			if (sscanf(item, "%zu", &tc->count) != 1)
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
		case 'd':
			tc->slen = strlen(item) / 2;
			if (process_bytes(tc->slen, &tc->salt, item))
				return TEST_CORRUPT;
			break;
		case 'p':
			tc->len = strlen(item) / 2;
			if (process_bytes(tc->len, &tc->pt, item))
				return TEST_CORRUPT;
			break;
		case 'c':
			tc->kdflen = strlen(item) / 2;
			if (process_bytes(tc->kdflen, &tc->ct, item))
				return TEST_CORRUPT;
			break;
	}

	return TEST_OK;
}

#define STUBS_API 1
#include "stubs.c"

struct generic {
	void *ctx;
	const void *functbl;
	void *priv;
};

static int make_new_ctx(const drew_loader_t *ldr, const char *name, void *ctx,
		int type)
{
	int id = -1, res = 0;
	struct generic *g = ctx;

	if ((id = res = drew_loader_lookup_by_name(ldr, name, 0, -1)) < 0)
		return res;

	if (drew_loader_get_type(ldr, id) != type)
		return -DREW_ERR_INVALID;

	if ((res = drew_loader_get_functbl(ldr, id, &g->functbl)) < 0)
		return res;

	return 0;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, keysz = 32, resultsz = 512, res = 0;
	uint8_t *buf, *key, *result;
	struct timespec cstart, cend;
	drew_kdf_t ctx;
	drew_param_t param, bparam, pparam;
	drew_hash_t hash;
	drew_block_t block;
	drew_kdf_t *prf = NULL;
	const char *balgo = NULL;

	if (!algo)
		algo = test_get_default_algo(ldr, name);

	if (!balgo)
		balgo = test_get_default_block_algo(ldr, name);

	if ((res = make_new_ctx(ldr, algo, &hash, DREW_TYPE_HASH)) < 0)
		return res;

	if ((res = make_new_ctx(ldr, balgo, &block, DREW_TYPE_BLOCK)) < 0)
		return res;

	if (strcmp(name, test_get_default_kdf_algo())) {
		prf = drew_mem_malloc(sizeof(*prf));
		if ((res = make_new_ctx(ldr, test_get_default_kdf_algo(), prf,
						DREW_TYPE_KDF)) < 0) {
			drew_mem_free(prf);
			prf = NULL;
		}
	}

	param.name = "digest";
	param.next = &bparam;
	param.param.value = &hash;

	bparam.name = "cipher";
	bparam.next = NULL;
	bparam.param.value = &block;

	pparam.name = "prf";
	pparam.next = NULL;
	pparam.param.value = prf;

	hash.functbl->init(&hash, 0, ldr, NULL);
	block.functbl->init(&block, 0, ldr, NULL);

	if (prf) {
		prf->functbl->init(prf, 0, ldr, &param);
		bparam.next = &pparam;
	}

	buf = drew_mem_calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	key = drew_mem_calloc(keysz, 1);
	if (!key)
		return ENOMEM;

	result = drew_mem_calloc(resultsz, 1);
	if (!result)
		return ENOMEM;

	ctx.functbl = tbl;

	clock_gettime(USED_CLOCK, &cstart);
	ctx.functbl->init(&ctx, 0, ldr, &param);
	ctx.functbl->setkey(&ctx, key, keysz);
	for (i = 0; i < nchunks; i++)
		ctx.functbl->generate(&ctx, buf, chunk, buf, chunk);
	clock_gettime(USED_CLOCK, &cend);
	ctx.functbl->fini(&ctx, 0);

	hash.functbl->fini(&hash, 0);
	block.functbl->fini(&block, 0);
	if (prf)
		prf->functbl->fini(prf, 0);

	drew_mem_free(prf);
	drew_mem_free(buf);
	drew_mem_free(key);
	drew_mem_free(result);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
