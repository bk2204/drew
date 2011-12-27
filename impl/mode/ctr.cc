/*-
 * Copyright © 2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#include "internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/mem.h>
#include <drew/mode.h>
#include <drew/block.h>
#include <drew/plugin.h>

#include "util.h"

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct ctr {
	const drew_loader_t *ldr;
	drew_block_t *algo;
	uint8_t ctr[32] ALIGNED_T;
	uint8_t buf[32] ALIGNED_T;
	uint8_t iv[32];
	size_t blksize;
	size_t boff;
};

static int ctr_info(int op, void *p);
static int ctr_info2(const drew_mode_t *, int op, drew_param_t *,
		const drew_param_t *);
static int ctr_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int ctr_reset(drew_mode_t *ctx);
static int ctr_resync(drew_mode_t *ctx);
static int ctr_setblock(drew_mode_t *ctx, const drew_block_t *algoctx);
static int ctr_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len);
static int ctr_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int ctr_encryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int ctr_fini(drew_mode_t *ctx, int flags);
static int ctr_test(void *p, const drew_loader_t *ldr);
static int ctr_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags);
static int ctr_setdata(drew_mode_t *, const uint8_t *, size_t);
static int ctr_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);
static int ctr_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);

static const drew_mode_functbl_t ctr_functbl = {
	ctr_info, ctr_info2, ctr_init, ctr_clone, ctr_reset, ctr_fini,
	ctr_setblock, ctr_setiv, ctr_encrypt, ctr_encrypt, ctr_encrypt, ctr_encrypt,
	ctr_setdata, ctr_encryptfinal, ctr_decryptfinal, ctr_resync, ctr_test
};

static const drew_mode_functbl_t ctr_functbl_aligned = {
	ctr_info, ctr_info2, ctr_init, ctr_clone, ctr_reset, ctr_fini,
	ctr_setblock, ctr_setiv, ctr_encrypt, ctr_encrypt, ctr_encryptfast,
	ctr_encryptfast, ctr_setdata, ctr_encryptfinal, ctr_decryptfinal,
	ctr_resync, ctr_test
};

static int ctr_info(int op, void *p)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct ctr);
		case DREW_MODE_FINAL_INSIZE:
		case DREW_MODE_FINAL_OUTSIZE:
			return 0;
		case DREW_MODE_QUANTUM:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int ctr_info2(const drew_mode_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct ctr);
		case DREW_MODE_FINAL_INSIZE_CTX:
		case DREW_MODE_FINAL_OUTSIZE_CTX:
			return 0;
		case DREW_MODE_BLKSIZE_CTX:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}


static int ctr_reset(drew_mode_t *ctx)
{
	struct ctr *c = ctx->ctx;
	int res = 0;

	if ((res = ctr_setiv(ctx, c->iv, c->blksize)))
		return res;
	c->boff = 0;
	return 0;
}

static int ctr_resync(drew_mode_t *ctx)
{
	return -DREW_ERR_NOT_IMPL;
}

static int ctr_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct ctr *newctx = ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = drew_mem_smalloc(sizeof(*newctx));
	memset(newctx, 0, sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->algo = NULL;
	newctx->boff = 0;

	ctx->ctx = newctx;
	ctx->functbl = &ctr_functbl;

	return 0;
}

static int ctr_setblock(drew_mode_t *ctx, const drew_block_t *algoctx)
{
	struct ctr *c = ctx->ctx;

	/* You really do need to pass something for the algoctx parameter, because
	 * otherwise you haven't set a key for the algorithm.  That's a bit bizarre,
	 * but we might allow it in the future (such as for PRNGs).
	 */
	if (!algoctx)
		return DREW_ERR_INVALID;

	if (c->algo) {
		c->algo->functbl->fini(c->algo, 0);
		drew_mem_free(c->algo);
	}
	c->algo = drew_mem_malloc(sizeof(*c->algo));
	c->algo->functbl = algoctx->functbl;
	c->algo->functbl->clone(c->algo, algoctx, 0);
	c->blksize = c->algo->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (c->blksize == FAST_ALIGNMENT)
		ctx->functbl = &ctr_functbl_aligned;

	return 0;
}

static int ctr_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len)
{
	struct ctr *c = ctx->ctx;

	if (c->blksize != len)
		return -DREW_ERR_INVALID;

	memcpy(c->ctr, iv, len);
	memcpy(c->buf, iv, len);
	if (iv != c->iv)
		memcpy(c->iv, iv, len);
	return 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void increment_counter(uint8_t *ctr, size_t len)
{
	bool carry = 0;
	carry = !++ctr[len - 1];
	for (int i = len - 2; unlikely(carry && i >= 0); i--) {
		if (!(carry = !++ctr[i]))
			break;
	}
}

static int ctr_encrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct ctr *c = ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	if (c->boff) {
		const size_t b = MIN(c->blksize - c->boff, len);
		for (size_t i = 0; i < b; i++)
			out[i] = c->buf[c->boff + i] ^ in[i];
		if ((c->boff += b) == c->blksize)
			c->boff = 0;
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->blksize) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->ctr);
		increment_counter(c->ctr, c->blksize);
		for (size_t i = 0; i < c->blksize; i++)
			out[i] = c->buf[i] ^ in[i];
		len -= c->blksize;
		out += c->blksize;
		in += c->blksize;
	}

	if (len) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->ctr);
		increment_counter(c->ctr, c->blksize);
		for (size_t i = 0; i < len; i++)
			out[i] = c->buf[i] ^ in[i];
		c->boff = len;
	}

	return 0;
}

static int ctr_encryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	struct ctr *c = ctx->ctx;
	uint8_t *outp = out;
	const uint8_t *inp = in;
	const size_t mul = len / c->blksize;

	for (size_t i = 0; i < len; i += FAST_ALIGNMENT, out += FAST_ALIGNMENT,
			in += FAST_ALIGNMENT) {
		memcpy(out, c->ctr, c->blksize);
		increment_counter(c->ctr, c->blksize);
	}
	c->algo->functbl->encryptfast(c->algo, outp, outp, mul);
	xor_aligned2(outp, inp, len);

	return 0;
}

static int ctr_setdata(drew_mode_t *ctx, const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

static int ctr_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	ctr_encrypt(ctx, out, in, inlen);
	return inlen;
}

static int ctr_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	ctr_encrypt(ctx, out, in, inlen);
	return inlen;
}

struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *iv;
	size_t ivsz;
	const uint8_t *input;
	const uint8_t *output;
	size_t datasz;
	size_t feedback;
};

static int ctr_test_generic(const drew_loader_t *ldr, const char *name,
		const struct test *testdata, size_t ntests)
{
	int id, result = 0;
	const drew_block_functbl_t *functbl;
	drew_block_t algo;
	drew_mode_t c;
	const void *tmp;
	uint8_t buf[128];

	id = drew_loader_lookup_by_name(ldr, name, 0, -1);
	if (id < 0)
		return id;

	drew_loader_get_functbl(ldr, id, &tmp);
	functbl = tmp;
	functbl->init(&algo, 0, ldr, NULL);

	for (size_t i = 0; i < ntests; i++) {
		drew_param_t param;

		memset(buf, 0, sizeof(buf));
		result <<= 1;

		param.name = "feedbackBits";
		param.next = NULL;
		param.param.number = testdata[i].feedback * 8;
		ctr_init(&c, 0, ldr, &param);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		ctr_setblock(&c, &algo);
		ctr_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		/* We use 9 here because it tests all three code paths for 64-bit
		 * blocks.
		 */
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ctr_encrypt(&c, buf+j, testdata[i].input+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].output, testdata[i].datasz);
		ctr_fini(&c, 0);
		algo.functbl->fini(&algo, 0);

		ctr_init(&c, 0, ldr, &param);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		ctr_setblock(&c, &algo);
		ctr_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ctr_encrypt(&c, buf+j, testdata[i].output+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].input, testdata[i].datasz);
		ctr_fini(&c, 0);
		algo.functbl->fini(&algo, 0);
	}
	
	return result;
}

static int ctr_test_aes128(const drew_loader_t *ldr, size_t *ntests)
{
	const uint8_t *key = (const uint8_t *)"\x2b\x7e\x15\x16\x28\xae\xd2\xa6"
				"\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
	const uint8_t *iv = (const uint8_t *)"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
				"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
	struct test testdata[] = {
		{
			key,
			16,
			iv,
			16,
			(const uint8_t *)
				"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
				"\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
				"\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
				"\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
				"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"
				"\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
			(const uint8_t *)
				"\x87\x4d\x61\x91\xb6\x20\xe3\x26"
				"\x1b\xef\x68\x64\x99\x0d\xb6\xce"
				"\x98\x06\xf6\x6b\x79\x70\xfd\xff"
				"\x86\x17\x18\x7b\xb9\xff\xfd\xff"
				"\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e"
				"\x5b\x4f\x09\x02\x0d\xb0\x3e\xab",
			48,
			1
		}
	};

	*ntests = DIM(testdata);

	return ctr_test_generic(ldr, "AES128", testdata, DIM(testdata));
}

static int ctr_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = ctr_test_aes128(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static int ctr_fini(drew_mode_t *ctx, int flags)
{
	struct ctr *c = ctx->ctx;

	if (c->algo)
		c->algo->functbl->fini(c->algo, 0);

	if (!(flags & DREW_MODE_FIXED)) {
		drew_mem_sfree(c);
		ctx->ctx = NULL;
	}

	return 0;
}

static int ctr_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags)
{
	struct ctr *c = oldctx->ctx, *cn;

	if (!(flags & DREW_MODE_FIXED))
		newctx->ctx = drew_mem_smalloc(sizeof(struct ctr));
	cn = newctx->ctx;
	memcpy(newctx->ctx, oldctx->ctx, sizeof(struct ctr));
	if (c->algo) {
		cn->algo = drew_mem_memdup(c->algo, sizeof(*c->algo));
		cn->algo->functbl->clone(cn->algo, c->algo, 0);
	}
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "CTR", &ctr_functbl },
	{ "Counter-BE", &ctr_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(ctr)(void *ldr, int op, int id, void *p)
{
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]);

	if (id < 0 || id >= nplugins)
		return -DREW_ERR_INVALID;

	switch (op) {
		case DREW_LOADER_LOOKUP_NAME:
			return 0;
		case DREW_LOADER_GET_NPLUGINS:
			return nplugins;
		case DREW_LOADER_GET_TYPE:
			return DREW_TYPE_MODE;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_mode_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_mode_functbl_t));
			return 0;
		case DREW_LOADER_GET_NAME_SIZE:
			return strlen(plugin_data[id].name) + 1;
		case DREW_LOADER_GET_NAME:
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1);
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}
UNEXPORT()
