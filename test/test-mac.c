/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different MACs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/mac.h>
#include <drew/hash.h>
#include <drew/block.h>

#define FILENAME "test/vectors-mac"

static int make_new_ctx(DrewLoader *ldr, const char *name, void *ctx,
		int type);

int test_get_type(void)
{
	return DREW_TYPE_MAC;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return "MD5";
}

const char *test_get_default_block_algo(drew_loader_t *ldr, const char *name)
{
	return "AES128";
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_mac_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

struct testcase {
	char *id;
	char *algo;
	char *mac;
	size_t klen;
	uint8_t *key;
	size_t len;
	size_t maclen;
	uint8_t *pt;
	uint8_t *ct;
	size_t nrepeats;
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
		free(tc->mac);
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

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	q->id = NULL;
	q->algo = strdup(p->algo);
	q->mac = strdup(p->mac);
	q->klen = p->klen;
	q->nrepeats = p->nrepeats;
	q->key = malloc(q->klen);
	memcpy(q->key, p->key, q->klen);
	q->len = p->len;
	q->pt = malloc(q->len);
	memcpy(q->pt, p->pt, q->len);
	q->ct = malloc(q->maclen);
	memcpy(q->ct, p->ct, q->maclen);

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
	if (!tc->mac)
		return TEST_CORRUPT;
	if (strcmp(name, tc->mac))
		return TEST_NOT_FOR_US;
	if (!tc->pt || !tc->ct)
		return TEST_CORRUPT;

	drew_mac_t ctx;
	drew_param_t param, tagparam;
	drew_hash_t hash;
	drew_block_t block;

	memset(&param, 0, sizeof(param));

	tagparam.name = "tagLength";
	tagparam.next = &param;
	tagparam.param.number = tc->maclen;

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

	uint8_t *buf = malloc(tc->maclen);
	ctx.functbl = tbl;
	ctx.functbl->init(&ctx, 0, tep->ldr, &tagparam);
	ctx.functbl->setkey(&ctx, tc->key, tc->klen);
	for (size_t i = 0; i < tc->nrepeats; i++)
		ctx.functbl->update(&ctx, tc->pt, tc->len);
	ctx.functbl->final(&ctx, buf, 0);
	ctx.functbl->fini(&ctx, 0);
	if (memcmp(buf, tc->ct, tc->maclen))
		res = TEST_FAILED;

	free(buf);
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
			break;
		case 'm':
			free(tc->mac);
			tc->mac = strdup(item);
			break;
		case 'r':
			if (sscanf(item, "%zu", &tc->nrepeats) != 1)
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
		case 'p':
			tc->len = strlen(item) / 2;
			if (process_bytes(tc->len, &tc->pt, item))
				return TEST_CORRUPT;
			break;
		case 'c':
			tc->maclen = strlen(item) / 2;
			if (process_bytes(tc->maclen, &tc->ct, item))
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

static int make_new_ctx(DrewLoader *ldr, const char *name, void *ctx,
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
		const void *tbl, int chunk, int nchunks, int flags)
{
	int i, keysz = 32, resultsz = 512, res = 0;
	uint8_t *buf, *key, *result;
	struct timespec cstart, cend;
	drew_mac_t ctx;
	drew_param_t param, bparam;
	drew_hash_t hash;
	drew_block_t block;
	const char *balgo = NULL;

	if (!algo)
		algo = test_get_default_algo(ldr, name);

	if (!balgo)
		balgo = test_get_default_block_algo(ldr, name);

	if ((res = make_new_ctx(ldr, algo, &hash, DREW_TYPE_HASH)) < 0)
		return res;

	if ((res = make_new_ctx(ldr, balgo, &block, DREW_TYPE_BLOCK)) < 0)
		return res;

	param.name = "digest";
	param.next = &bparam;
	param.param.value = &hash;

	bparam.name = "cipher";
	bparam.next = NULL;
	bparam.param.value = &block;

	hash.functbl->init(&hash, 0, ldr, NULL);
	block.functbl->init(&block, 0, ldr, NULL);

	buf = calloc(chunk, 1);
	if (!buf)
		return ENOMEM;

	key = calloc(keysz, 1);
	if (!key)
		return ENOMEM;

	result = calloc(resultsz, 1);
	if (!result)
		return ENOMEM;

	ctx.functbl = tbl;

	clock_gettime(USED_CLOCK, &cstart);
	ctx.functbl->init(&ctx, 0, ldr, &param);
	ctx.functbl->setkey(&ctx, key, keysz);
	for (i = 0; i < nchunks; i++)
		ctx.functbl->update(&ctx, buf, chunk);
	ctx.functbl->final(&ctx, result, 0);
	clock_gettime(USED_CLOCK, &cend);
	ctx.functbl->fini(&ctx, 0);

	free(buf);
	free(key);
	free(result);

	hash.functbl->fini(&hash, 0);
	block.functbl->fini(&block, 0);

	print_speed_info(chunk, nchunks, &cstart, &cend);
	
	return 0;
}
