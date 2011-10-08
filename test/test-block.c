/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
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

void *test_clone_data(void *tc, int flags)
{
	struct testcase *q = test_create_data();
	struct testcase *p = tc;

	q->id = NULL;
	q->algo = strdup(p->algo);
	q->klen = p->klen;
	q->blksize = p->blksize;
	q->key = malloc(q->klen);
	memcpy(q->key, p->key, q->klen);
	q->pt = malloc(q->blksize);
	memcpy(q->pt, p->pt, q->blksize);
	q->ct = malloc(q->blksize);
	memcpy(q->ct, p->ct, q->blksize);
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

// The version is not what it's supposed to be.
#define BLOCK_BAD_VERSION		(1 <<  0)
// The block is using errno values for things other than ENOMEM.
#define BLOCK_BAD_ERRNO			(1 <<  1)
// The block is using very odd values (non-power-of-two) for the quantum.
#define BLOCK_BAD_QUANTUM		(1 <<  2)
#define BLOCK_BAD_BLKSIZE		(1 <<  3)
#define BLOCK_BAD_KEYSIZE		(1 <<  4)
#define BLOCK_BAD_ENDIAN		(1 <<  5)
#define BLOCK_BAD_INTSIZE		(1 <<  6)
#define BLOCK_BAD_NULLIFY		(1 <<  7)
#define BLOCK_BAD_INIT			(1 <<  8)
#define BLOCK_BAD_FUNCTBL		(1 <<  9)
#define BLOCK_BAD_SETKEY		(1 << 10)
#define BLOCK_BAD_CLONE			(1 << 11)
#define BLOCK_BAD_ENCRYPT		(1 << 12)
#define BLOCK_BAD_DECRYPT		(1 << 13)
#define BLOCK_BAD_ENCRYPTFAST	(1 << 14)
#define BLOCK_BAD_DECRYPTFAST	(1 << 15)
// Somehow, the clone was detected.
#define BLOCK_BAD_CRACK			(1 << 16)
#define BLOCK_BAD_FINI			(1 << 17)
#define BLOCK_BAD_ERROR			(1 << 18)
#define BLOCK_BAD_RESET			(1 << 19)

int test_api_context(drew_block_t *ctx, const drew_loader_t *ldr,
		const drew_param_t *paramp, size_t intsize, size_t blocksize,
		size_t keysize)
{
	int flag = ctx->ctx ? DREW_BLOCK_FIXED : 0;
	const drew_param_t *param = paramp->name ? paramp : NULL;
	int retval = 0;
	uint8_t *buf;
	const size_t page = 4096, niters = 4;
	drew_block_t clone[3];

	// One page, please.
	posix_memalign((void **)&buf, 16, page*2);
	memset(buf, 0xe1, page*2);

	if (ctx->functbl->init(ctx, flag, ldr, param)) {
		retval |= BLOCK_BAD_INIT;
		return retval;
	}

	if (ctx->functbl->setkey(ctx, buf, keysize, 0))
		retval |= BLOCK_BAD_SETKEY;

	if (ctx->functbl->encryptfast(ctx, buf, buf, niters))
		retval |= BLOCK_BAD_ENCRYPTFAST;

	// Buffer: EN (first half encrypted, second half normal).
	if (ctx->functbl->clone(&clone[0], ctx, 0) ||
		clone[0].functbl != ctx->functbl || clone[0].ctx == ctx->ctx)
		retval |= BLOCK_BAD_CLONE;

	for (size_t i = 0; i < niters; i++) {
		const size_t off = i * blocksize;
		if (ctx->functbl->encrypt(ctx, buf+2048+off, buf+2048+off))
			retval |= BLOCK_BAD_ENCRYPT;
	}
	
	// Buffer: EE.
	// Decrypt the beginning of the buffer.
	for (size_t i = 0; i < niters; i++) {
		const size_t off = i * blocksize;
		if (clone[0].functbl->decrypt(&clone[0], buf+off, buf+off))
			retval |= BLOCK_BAD_DECRYPT;
	}

	// Buffer: NE.
	if (ctx->functbl->clone(&clone[1], ctx, 0) ||
		clone[1].functbl != ctx->functbl || clone[1].ctx == ctx->ctx)
		retval |= BLOCK_BAD_CLONE;

	// Use the data we've encrypted as the key.
	if (ctx->functbl->setkey(ctx, buf+2048, keysize, 0))
		retval |= BLOCK_BAD_SETKEY;

	if (clone[0].functbl->setkey(&clone[0], buf+2048, keysize, 0))
		retval |= BLOCK_BAD_SETKEY;

	// Now decrypt that area.
	if (clone[1].functbl->decryptfast(&clone[1], buf+2048, buf+2048, niters))
		retval |= BLOCK_BAD_DECRYPTFAST;

	// Buffer: NN.
	if (clone[1].functbl->fini(&clone[1], 0))
		retval |= BLOCK_BAD_FINI;

	if (clone[0].functbl->clone(&clone[2], &clone[0], 0) ||
		clone[2].functbl != clone[0].functbl || clone[2].ctx == clone[0].ctx)
		retval |= BLOCK_BAD_CLONE;

	if (clone[0].functbl->fini(&clone[0], 0))
		retval |= BLOCK_BAD_FINI;

	if (clone[2].functbl->reset(ctx))
		retval |= BLOCK_BAD_RESET;

	if (clone[2].functbl->encryptfast(&clone[2], buf, buf, niters))
		retval |= BLOCK_BAD_ENCRYPTFAST;

	if (ctx->functbl->decryptfast(ctx, buf, buf, niters))
		retval |= BLOCK_BAD_DECRYPTFAST;

	if (memcmp(buf, buf+page, page))
		retval |= BLOCK_BAD_CRACK;

	if (clone[2].functbl->fini(&clone[2], 0))
		retval |= BLOCK_BAD_FINI;

	if (ctx->functbl->fini(ctx, flag))
		retval |= BLOCK_BAD_FINI;

	free(buf);

	return retval;
}

int test_api(const drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl)
{
	int res = 0, retval = 0, quantum = 1;
	size_t intsize = 0, blocksize = 0, keysize = 0;
	drew_block_t c, *ctx = &c;
	void *mem;

	// Make sure our functinos are not NULL.
	int (*p)() = tbl;
	for (int i = 0; i < sizeof(*ctx->functbl)/sizeof(p); i++, p++)
		if (!p) {
			retval |= BLOCK_BAD_FUNCTBL;
			return retval;
		}

	ctx->functbl = tbl;
	res = ctx->functbl->info(DREW_BLOCK_VERSION, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res != 2)
		retval |= BLOCK_BAD_VERSION;

	res = ctx->functbl->info(DREW_BLOCK_QUANTUM, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res < 0)
		retval |= BLOCK_BAD_QUANTUM;
	else {
		if (res & (res-1))
			retval |= BLOCK_BAD_QUANTUM;
		quantum = res;
	}

	res = ctx->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res < 0 || res > (512/8) || (res % quantum))
		retval |= BLOCK_BAD_BLKSIZE;
	else
		blocksize = res;

	res = ctx->functbl->info(DREW_BLOCK_ENDIAN, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res && res != 4321 && res != 1234)
		retval |= BLOCK_BAD_ENDIAN;

	res = ctx->functbl->info(DREW_BLOCK_INTSIZE, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res <= 0 || res >= 65536)
		retval |= BLOCK_BAD_INTSIZE;
	else
		intsize = res;

	res = ctx->functbl->info(0xdeadbeef, NULL);
	if (is_forbidden_errno(res))
		retval |= BLOCK_BAD_ERRNO;
	if (res != -DREW_ERR_INVALID)
		retval |= BLOCK_BAD_ERROR;

	for (;;) {
		res = ctx->functbl->info(DREW_BLOCK_KEYSIZE, &keysize);
		if (is_forbidden_errno(res))
			retval |= BLOCK_BAD_ERRNO;
		if (!res)
			break;
		if (res < 0 || res > (4096/8))
			retval |= BLOCK_BAD_KEYSIZE;
		else
			keysize = res;

		ctx->ctx = NULL;
		retval |= test_api_context(ctx, ldr, NULL, intsize, blocksize, keysize);
		if (ctx->ctx)
			retval |= BLOCK_BAD_NULLIFY;
		ctx->ctx = mem = malloc(intsize);
		retval |= test_api_context(ctx, ldr, NULL, intsize, blocksize, keysize);
		if (ctx->ctx != mem)
			retval |= BLOCK_BAD_NULLIFY;
		free(mem);
	}

	return retval;
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
