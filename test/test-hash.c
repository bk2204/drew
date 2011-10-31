/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
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
		int chunk, int nchunks, int hashsize, 
		int (*update)(drew_hash_t *, const uint8_t *, size_t))
{
	int i;

	for (i = 0; !framework_sigflag && i < nchunks; i++)
		update(ctx, buf, chunk);
	if (!framework_sigflag)
		ctx->functbl->final(ctx, buf, hashsize, 0);
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

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	q->id = NULL;
	q->algo = strdup(p->algo);
	q->nrepeats = p->nrepeats;
	q->insize = p->insize;
	q->in = malloc(q->insize);
	memcpy(q->in, p->in, q->insize);
	q->digestsize = p->digestsize;
	q->digest = malloc(q->digestsize);
	memcpy(q->digest, p->digest, q->digestsize);

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
	ctx.functbl->final(&ctx, buf, tc->digestsize, 0);
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

// The version is not what it's supposed to be.
#define HASH_BAD_VERSION	(1 <<  0)
// The hash is using errno values for things other than ENOMEM.
#define HASH_BAD_ERRNO		(1 <<  1)
// The hash is using very odd values (non-power-of-two) for the quantum.
#define HASH_BAD_QUANTUM	(1 <<  2)
#define HASH_BAD_SIZE		(1 <<  3)
#define HASH_BAD_BLKSIZE	(1 <<  4)
#define HASH_BAD_BUFSIZE	(1 <<  5)
#define HASH_BAD_ENDIAN		(1 <<  6)
#define HASH_BAD_INTSIZE	(1 <<  7)
#define HASH_BAD_NULLIFY	(1 <<  8)
#define HASH_BAD_INIT		(1 <<  9)
#define HASH_BAD_FUNCTBL	(1 << 10)
#define HASH_BAD_UPDATEFAST	(1 << 11)
#define HASH_BAD_CLONE		(1 << 12)
#define HASH_BAD_UPDATE		(1 << 13)
// Somehow, the clone was detected.
#define HASH_BAD_CRACK		(1 << 14)
#define HASH_BAD_PAD		(1 << 15)
#define HASH_BAD_FINAL		(1 << 16)
#define HASH_BAD_FINI		(1 << 17)
#define HASH_BAD_ERROR		(1 << 18)

int test_api_context(drew_hash_t *ctx, const drew_loader_t *ldr,
		const drew_param_t *paramp, size_t intsize, size_t hashsize,
		size_t quantum)
{
	int flag = ctx->ctx ? DREW_HASH_FIXED : 0;
	const drew_param_t *param = paramp->name ? paramp : NULL;
	int retval = 0, res;
	uint8_t *buf;
	const size_t page = 4096;
	drew_hash_t clone[2], *newctx = clone;

	// One page, please.
	posix_memalign((void **)&buf, 16, page);
	memset(buf, 0xe1, page);

	if (ctx->functbl->init(ctx, flag, ldr, param)) {
		retval |= HASH_BAD_INIT;
		return retval;
	}

	res = ctx->functbl->info(DREW_HASH_BLKSIZE, ctx);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res < 0 || res > (4096/8))
		retval |= HASH_BAD_BLKSIZE;

	res = ctx->functbl->info(DREW_HASH_BUFSIZE, ctx);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res < 0 || res > (4096/8) || res % quantum)
		retval |= HASH_BAD_BUFSIZE;

	if (ctx->functbl->updatefast(ctx, buf, page))
		retval |= HASH_BAD_UPDATEFAST;

	if (ctx->functbl->clone(newctx, ctx, 0) ||
		newctx->functbl != ctx->functbl || newctx->ctx == ctx->ctx)
		retval |= HASH_BAD_CLONE;

	if (ctx->functbl->updatefast(ctx, buf, page))
		retval |= HASH_BAD_UPDATEFAST;

	if (ctx->functbl->update(ctx, buf, (page/2)+1))
		retval |= HASH_BAD_UPDATE;

	if (newctx->functbl->update(newctx, buf, page))
		retval |= HASH_BAD_UPDATE;

	if (newctx->functbl->update(newctx, buf, (page/2)+1))
		retval |= HASH_BAD_UPDATE;

	if (ctx->functbl->clone(&clone[1], ctx, 0) ||
		clone[1].functbl != ctx->functbl || clone[1].ctx == ctx->ctx)
		retval |= HASH_BAD_CLONE;

	if (ctx->functbl->update(ctx, buf, page))
		retval |= HASH_BAD_UPDATE;

	if (newctx->functbl->update(newctx, buf, page))
		retval |= HASH_BAD_UPDATE;

	if (clone[1].functbl->update(&clone[1], buf, page))
		retval |= HASH_BAD_UPDATE;

	if (ctx->functbl->pad(ctx))
		retval |= HASH_BAD_PAD;

	if (ctx->functbl->final(ctx, buf, hashsize, DREW_HASH_NO_PAD))
		retval |= HASH_BAD_FINAL;

	if (newctx->functbl->final(newctx, buf+hashsize, hashsize, 0))
		retval |= HASH_BAD_FINAL;

	if (clone[1].functbl->final(&clone[1], buf+(hashsize*2), hashsize, 0))
		retval |= HASH_BAD_FINAL;

	if (memcmp(buf, buf+hashsize, hashsize))
		retval |= HASH_BAD_CRACK;

	if (memcmp(buf, buf+(hashsize*2), hashsize))
		retval |= HASH_BAD_CRACK;

	if (clone[1].functbl->fini(&clone[1], 0))
		retval |= HASH_BAD_FINI;

	if (newctx->functbl->fini(newctx, 0))
		retval |= HASH_BAD_FINI;

	if (ctx->functbl->fini(ctx, flag))
		retval |= HASH_BAD_FINI;

	free(buf);

	return retval;
}

int test_api(const drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl)
{
	int res = 0, retval = 0, quantum = 1;
	size_t intsize = 0, hashsize = 0;
	drew_hash_t c, *ctx = &c;
	drew_param_t param;
	void *mem;

	memset(&param, 0, sizeof(param));

	// Make sure our functinos are not NULL.
	int (*p)() = tbl;
	for (int i = 0; i < sizeof(*ctx->functbl)/sizeof(p); i++, p++)
		if (!p) {
			retval |= HASH_BAD_FUNCTBL;
			return retval;
		}

	ctx->functbl = tbl;
	res = ctx->functbl->info(DREW_HASH_VERSION, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res != 3)
		retval |= HASH_BAD_VERSION;

	if (res < 3) {
		res = ctx->functbl->info(DREW_HASH_QUANTUM, NULL);
		if (is_forbidden_errno(res))
			retval |= HASH_BAD_ERRNO;
		if (res < 0)
			retval |= HASH_BAD_QUANTUM;
		else {
			if (res & (res-1))
				retval |= HASH_BAD_QUANTUM;
			quantum = res;
		}
	}

	res = ctx->functbl->info(DREW_HASH_SIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res == -DREW_ERR_MORE_INFO) {
		size_t vals[] = {1024, 512, 384, 256, 224, 192, 160, 128, 32, 24, 16};
		for (int i = 0; i < DIM(vals); i++) {
			param.name = "digestSize";
			param.param.number = vals[i] / 8;
			param.next = NULL;
			res = ctx->functbl->info(DREW_HASH_SIZE, &param);
			if (res == param.param.number)
				break;
			if (res != -DREW_ERR_MORE_INFO && res != -DREW_ERR_INVALID)
				break;
		}
	}
	if (res < 0 || res > (1024/8))
		retval |= HASH_BAD_SIZE;
	else
		hashsize = res;

	res = ctx->functbl->info(DREW_HASH_BLKSIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if ((res < 0 && res != -DREW_ERR_MORE_INFO) || res > (4096/8))
		retval |= HASH_BAD_BLKSIZE;

	res = ctx->functbl->info(DREW_HASH_BUFSIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if ((res < 0 && res != -DREW_ERR_MORE_INFO) || res > (4096/8) ||
			((res > 0) && (res % quantum)))
		retval |= HASH_BAD_BUFSIZE;

	res = ctx->functbl->info(DREW_HASH_ENDIAN, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res && res != 4321 && res != 1234)
		retval |= HASH_BAD_ENDIAN;

	res = ctx->functbl->info(DREW_HASH_INTSIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res < 0 || res >= 1000)
		retval |= HASH_BAD_INTSIZE;
	else
		intsize = res;

	res = ctx->functbl->info(0xdeadbeef, NULL);
	if (is_forbidden_errno(res))
		retval |= HASH_BAD_ERRNO;
	if (res != -DREW_ERR_INVALID)
		retval |= HASH_BAD_ERROR;

	ctx->ctx = NULL;
	retval |= test_api_context(ctx, ldr, &param, intsize, hashsize, quantum);
	if (ctx->ctx)
		retval |= HASH_BAD_NULLIFY;
	ctx->ctx = mem = malloc(intsize);
	retval |= test_api_context(ctx, ldr, &param, intsize, hashsize, quantum);
	if (ctx->ctx != mem)
		retval |= HASH_BAD_NULLIFY;
	free(mem);

	return retval;
}

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	int i, res, blksize, hashsize;
	uint8_t *buf;
	struct timespec cstart, cend;
	drew_hash_t ctx;
	void *fwdata;
	int (*update)(drew_hash_t *, const uint8_t *, size_t);

	if ((res = posix_memalign((void **)&buf, DREW_HASH_ALIGNMENT, chunk)))
		return res;

	ctx.functbl = tbl;
	blksize = ctx.functbl->info(DREW_HASH_BLKSIZE, NULL);
	if (blksize == -DREW_ERR_MORE_INFO)
		blksize = chunk + 1;
	else if (blksize <= 0)
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

	drew_param_t param;
	param.name = "context";
	param.next = NULL;
	param.param.value = &ctx;
	hashsize = ctx.functbl->info2(DREW_HASH_SIZE_CTX, NULL, &param);
	update = (!(chunk % blksize) && !(chunk % DREW_HASH_ALIGNMENT)) ? 
		ctx.functbl->updatefast : ctx.functbl->update;
	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(&ctx, buf, chunk, nchunks, hashsize, update);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);

	print_speed_info(chunk, i, &cstart, &cend);
	
	return 0;
}
