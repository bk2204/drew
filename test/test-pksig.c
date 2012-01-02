/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different PKSIGs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/pksig.h>

#define FILENAME "test/vectors-pksig"

int test_get_type(void)
{
	return DREW_TYPE_PKSIG;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_pksig_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

#define STUBS_API 1
#include "stubs.c"

struct testcase {
	char *id;
	char *algo;
	int flags; /* 1: don't sign, 2: don't verify. */
	size_t keysize[256];
	uint8_t *key[256];
	size_t insize[256];
	uint8_t *in[256];
	size_t outsize[256];
	uint8_t *out[256];
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
		for (int i = 0; i < 256; i++) {
			free(tc->key[i]);
			free(tc->in[i]);
			free(tc->out[i]);
		}
		memset(p, 0, sizeof(struct testcase));
	}
	if (flags & TEST_RESET_ZERO)
		memset(p, 0, sizeof(struct testcase));
}

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	q->id = NULL;
	q->algo = strdup(p->algo);
	memcpy(q->insize, p->insize, sizeof(q->insize));
	memcpy(q->outsize, p->outsize, sizeof(q->outsize));
	for (int i = 0; i < 256; i++) {
		if (p->key[i]) {
			q->key[i] = malloc(q->keysize[i]);
			memcpy(q->key[i], p->key[i], q->keysize[i]);
		}
		if (p->in[i]) {
			q->in[i] = malloc(q->insize[i]);
			memcpy(q->in[i], p->in[i], q->insize[i]);
		}
		if (p->out[i]) {
			q->out[i] = malloc(q->outsize[i]);
			memcpy(q->out[i], p->out[i], q->outsize[i]);
		}
	}

	return q;
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

int make_bignum(drew_bignum_t *bn, const uint8_t *data, size_t len,
		struct test_external *tep)
{
	int res = 0, id = 0;
	const void *tbl;

	if ((id = drew_loader_lookup_by_name(tep->ldr, "Bignum", 0, -1)) < 0)
		return id;
	if ((res = drew_loader_get_functbl(tep->ldr, id, &tbl)) < 0)
		return res;
	bn->functbl = tbl;
	if ((res = bn->functbl->init(bn, 0, tep->ldr, NULL)) < 0)
		return res;
	if (data && len)
		bn->functbl->setbytes(bn, data, len);
	return 0;
}

int test_execute(void *data, const char *name, const void *tbl,
		struct test_external *tep)
{
	int result = 0, res = 0;
	struct testcase *tc = data;
	// If the test isn't for us or is corrupt, we succeed since it isn't
	// relevant for our case.
	if (!tc->algo)
		return TEST_CORRUPT;
	if (strcmp(name, tc->algo))
		return TEST_NOT_FOR_US;
	if (tc->flags < 0 || tc->flags > 2)
		return TEST_CORRUPT;

	drew_pksig_t ctx;
	drew_bignum_t bn;
	drew_param_t ctxparam;
	int nin, nout;
	drew_bignum_t *inbuf = malloc(256 * sizeof(*inbuf));
	drew_bignum_t *outbuf = malloc(256 * sizeof(*outbuf));
	drew_bignum_t *cmpbuf = malloc(256 * sizeof(*cmpbuf));

	make_bignum(&bn, NULL, 0, tep);
	ctxparam.name = "bignum";
	ctxparam.next = NULL;
	ctxparam.param.value = &bn;
	ctx.functbl = tbl;
	if ((result = ctx.functbl->init(&ctx, 0, tep->ldr, &ctxparam)))
		return result;
	for (int i = 0; i < 256; i++) {
		char buf[2] = {0, 0};
		buf[0] = i;
		if (tc->key[i])
			if ((res = ctx.functbl->setval(&ctx, buf, tc->key[i], tc->keysize[i])) < 0)
				return res;
	}
	if (!(tc->flags & 1)) {
		nin = ctx.functbl->info(DREW_PKSIG_SIGN_IN, NULL);
		nout = ctx.functbl->info(DREW_PKSIG_SIGN_OUT, NULL);
		for (int i = 0; i < nin; i++) {
			drew_param_t param;
			int c;
			param.param.number = i;
			if ((result = ctx.functbl->info(DREW_PKSIG_SIGN_IN_INDEX_TO_NAME,
							&param)))
				return result;
			c = param.param.string[0];
			if ((res = make_bignum(&inbuf[i], tc->in[c], tc->insize[c], tep)))
				return res;
		}
		for (int i = 0; i < nout; i++) {
			drew_param_t param;
			int c;
			param.param.number = i;
			if ((result = ctx.functbl->info(DREW_PKSIG_SIGN_OUT_INDEX_TO_NAME,
							&param)))
				return result;
			c = param.param.string[0];
			if ((result = make_bignum(&outbuf[i], tc->out[c], tc->outsize[c], tep)))
				return result;
			if ((result = make_bignum(&cmpbuf[i], NULL, 0, tep)))
				return result;
		}
		if ((res = ctx.functbl->sign(&ctx, cmpbuf, inbuf)) < 0)
			return res;
		for (int i = 0; i < nout; i++)
			if (outbuf[i].functbl->compare(&outbuf[i], &cmpbuf[i], 0))
				return TEST_FAILED;
	}
	if (!(tc->flags & 2)) {
		nin = ctx.functbl->info(DREW_PKSIG_VERIFY_IN, NULL);
		nout = ctx.functbl->info(DREW_PKSIG_VERIFY_OUT, NULL);
		for (int i = 0; i < nin; i++) {
			drew_param_t param;
			int c;
			const uint8_t *p;
			size_t len;
			param.param.number = i;
			if ((result = ctx.functbl->info(DREW_PKSIG_VERIFY_IN_INDEX_TO_NAME,
							&param)))
				return result;
			c = param.param.string[0];
			if (tc->out[c]) {
				p = tc->out[c];
				len = tc->outsize[c];
			}
			else {
				p = tc->in[c];
				len = tc->insize[c];
			}
			if ((result = make_bignum(&inbuf[i], p, len, tep)))
				return result;
		}
		for (int i = 0; i < nout; i++) {
			drew_param_t param;
			int c;
			const uint8_t *p;
			size_t len;
			param.param.number = i;
			if ((result = ctx.functbl->info(DREW_PKSIG_VERIFY_OUT_INDEX_TO_NAME,
							&param)))
				return result;
			c = param.param.string[0];
			if (tc->in[c]) {
				p = tc->in[c];
				len = tc->insize[c];
			}
			else {
				p = tc->out[c];
				len = tc->outsize[c];
			}
			if ((result = make_bignum(&outbuf[i], p, len, tep)))
				return result;
		}
		if ((res = ctx.functbl->verify(&ctx, cmpbuf, inbuf)) < 0)
			return res;
		for (int i = 0; i < nout; i++)
			if (outbuf[i].functbl->compare(&outbuf[i], &cmpbuf[i], 0))
				return TEST_FAILED;
	}
	ctx.functbl->fini(&ctx, 0);

	free(inbuf);
	free(outbuf);
	free(cmpbuf);
	return result;
}

int test_process_testcase(void *data, int type, const char *item,
		struct test_external *tep)
{
	struct testcase *tc = data;
	int name = *item;
	const char *mpiitem = item + 1;

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
		case 'f':
			tc->flags = atoi(item);
			break;
		case 'k':
			if (!name)
				return TEST_CORRUPT;
			tc->keysize[name] = strlen(mpiitem) / 2;
			if (process_bytes(tc->keysize[name], &tc->key[name], mpiitem))
				return TEST_CORRUPT;
			break;
		case 'p':
			if (!name)
				return TEST_CORRUPT;
			tc->insize[name] = strlen(mpiitem) / 2;
			if (process_bytes(tc->insize[name], &tc->in[name], mpiitem))
				return TEST_CORRUPT;
			break;
		case 'c':
			if (!name)
				return TEST_CORRUPT;
			tc->outsize[name] = strlen(mpiitem) / 2;
			if (process_bytes(tc->outsize[name], &tc->out[name], mpiitem))
				return TEST_CORRUPT;
			break;
	}

	return TEST_OK;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}
