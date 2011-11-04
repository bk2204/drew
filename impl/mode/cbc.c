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
/* This is a C99 implementation of CBC, known in French as Radio-Canada. */

#include "internal.h"
#include "util.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/mem.h>
#include <drew/mode.h>
#include <drew/block.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct cbc {
	const drew_loader_t *ldr;
	drew_block_t *algo;
	uint8_t *buf;
	uint8_t *iv;
	size_t blksize;
};

static int cbc_info(int op, void *p);
static int cbc_info2(const drew_mode_t *, int op, drew_param_t *,
		const drew_param_t *);
static int cbc_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int cbc_reset(drew_mode_t *ctx);
static int cbc_resync(drew_mode_t *ctx);
static int cbc_setblock(drew_mode_t *ctx, const drew_block_t *algoctx);
static int cbc_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len);
static int cbc_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cbc_decrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cbc_fini(drew_mode_t *ctx, int flags);
static int cbc_test(void *p, const drew_loader_t *ldr);
static int cbc_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags);
static int cbc_setdata(drew_mode_t *, const uint8_t *, size_t);
static int cbc_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);
static int cbc_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);

static const drew_mode_functbl_t cbc_functbl = {
	cbc_info, cbc_info2, cbc_init, cbc_clone, cbc_reset, cbc_fini,
	cbc_setblock, cbc_setiv, cbc_encrypt, cbc_decrypt, cbc_encrypt, cbc_decrypt,
	cbc_setdata, cbc_encryptfinal, cbc_decryptfinal, cbc_resync, cbc_test
};

static int cbc_info(int op, void *p)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct cbc);
		case DREW_MODE_FINAL_INSIZE:
		case DREW_MODE_FINAL_OUTSIZE:
			return 0;
		case DREW_MODE_QUANTUM:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int cbc_info2(const drew_mode_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	struct cbc *c = NULL;

	if (ctx && ctx->ctx)
		c = ctx->ctx;

	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct cbc);
		case DREW_MODE_FINAL_INSIZE_CTX:
		case DREW_MODE_FINAL_OUTSIZE_CTX:
			return 0;
		case DREW_MODE_BLKSIZE_CTX:
			if (!c || !c->algo)
				return -DREW_ERR_MORE_INFO;
			return c->algo->functbl->info2(c->algo, DREW_BLOCK_BLKSIZE_CTX,
					NULL, NULL);
		default:
			return -DREW_ERR_INVALID;
	}
}


static int cbc_reset(drew_mode_t *ctx)
{
	struct cbc *c = ctx->ctx;
	int res = 0;

	if ((res = cbc_setiv(ctx, c->iv, c->blksize)))
		return res;
	return 0;
}

static int cbc_resync(drew_mode_t *ctx)
{
	return -DREW_ERR_NOT_IMPL;
}

static int cbc_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct cbc *newctx = ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = drew_mem_malloc(sizeof(*newctx));
	memset(newctx, 0, sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->algo = NULL;
	
	ctx->ctx = newctx;
	ctx->functbl = &cbc_functbl;

	return 0;
}

static int cbc_setpad(drew_mode_t *ctx, const drew_pad_t *algoname)
{
	return -DREW_ERR_NOT_IMPL;
}

static int cbc_setblock(drew_mode_t *ctx, const drew_block_t *algoctx)
{
	struct cbc *c = ctx->ctx;

	/* You really do need to pass something for the algoctx parameter, because
	 * otherwise you haven't set a key for the algorithm.  That's a bit bizarre,
	 * but we might allow it in the future (such as for PRNGs).
	 */
	if (!algoctx)
		return -DREW_ERR_INVALID;

	c->algo = drew_mem_malloc(sizeof(*c->algo));
	c->algo->functbl = algoctx->functbl;
	c->algo->functbl->clone(c->algo, algoctx, 0);
	c->blksize = c->algo->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (!(c->buf = drew_mem_smalloc(c->blksize)))
		return -ENOMEM;
	if (!(c->iv = drew_mem_smalloc(c->blksize)))
		return -ENOMEM;

	return 0;
}

static int cbc_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len)
{
	struct cbc *c = ctx->ctx;

	if (c->blksize != len)
		return -DREW_ERR_INVALID;

	memcpy(c->buf, iv, len);
	if (iv != c->iv)
		memcpy(c->iv, iv, len);
	return 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static int cbc_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	struct cbc *c = ctx->ctx;
	const size_t bs = c->blksize;

	if (len % bs)
		return -DREW_ERR_INVALID;

	for (; len >= bs; len -= bs, out += bs, in += bs) {
		for (size_t i = 0; i < bs; i++)
			c->buf[i] ^= in[i];
		c->algo->functbl->encrypt(c->algo, c->buf, c->buf);
		memcpy(out, c->buf, bs);
	}

	return 0;
}

static int cbc_decrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	struct cbc *c = ctx->ctx;
	const size_t bs = c->blksize;

	if (len % bs)
		return -DREW_ERR_INVALID;

	for (; len >= bs; len -= bs, out += bs, in += bs) {
		c->algo->functbl->decrypt(c->algo, out, in);
		for (size_t i = 0; i < bs; i++)
			out[i] ^= c->buf[i];
		memcpy(c->buf, in, bs);
	}

	return 0;
}

static int cbc_setdata(drew_mode_t *ctx, const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

static int cbc_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	cbc_encrypt(ctx, out, in, inlen);
	return inlen;
}

static int cbc_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	cbc_decrypt(ctx, out, in, inlen);
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
};

static int cbc_test_generic(const drew_loader_t *ldr, const char *name,
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
		memset(buf, 0, sizeof(buf));
		result <<= 1;

		cbc_init(&c, 0, ldr, NULL);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		cbc_setblock(&c, &algo);
		cbc_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		cbc_encrypt(&c, buf, testdata[i].input,
				MIN(sizeof(buf), testdata[i].datasz));

		result |= !!memcmp(buf, testdata[i].output, testdata[i].datasz);
		cbc_fini(&c, 0);
		algo.functbl->fini(&algo, 0);

		cbc_init(&c, 0, ldr, NULL);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		cbc_setblock(&c, &algo);
		cbc_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		cbc_decrypt(&c, buf, testdata[i].output,
				MIN(sizeof(buf), testdata[i].datasz));

		result |= !!memcmp(buf, testdata[i].input, testdata[i].datasz);
		cbc_fini(&c, 0);
		algo.functbl->fini(&algo, 0);
	}
	
	return result;
}

static int cbc_test_blowfish(const drew_loader_t *ldr, size_t *ntests)
{
	struct test testdata[] = {
		{
			(const uint8_t *)"\x01\x23\x45\x67\x89\xab\xcd\xef"
				"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
			16,
			(const uint8_t *)"\xfe\xdc\xba\x98\x76\x54\x32\x10",
			8,
			(const uint8_t *)"7654321 Now is the time for ",
			(const uint8_t *)"\x6b\x77\xb4\xd6\x30\x06\xde\xe6"
				"\x05\xb1\x56\xe2\x74\x03\x97\x93"
				"\x58\xde\xb9\xe7\x15\x46\x16\xd9",
			24
		}
	};

	*ntests = DIM(testdata);

	return cbc_test_generic(ldr, "Blowfish", testdata, DIM(testdata));
}

static int cbc_test_aes128(const drew_loader_t *ldr, size_t *ntests)
{
	const uint8_t *key = (const uint8_t *)"\x2b\x7e\x15\x16\x28\xae\xd2\xa6"
				"\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
	const uint8_t *iv = (const uint8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07"
				"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
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
				"\x76\x49\xab\xac\x81\x19\xb2\x46"
				"\xce\xe9\x8e\x9b\x12\xe9\x19\x7d"
				"\x50\x86\xcb\x9b\x50\x72\x19\xee"
				"\x95\xdb\x11\x3a\x91\x76\x78\xb2"
				"\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b"
				"\x71\x16\xe6\x9e\x22\x22\x95\x16",
			48,
		}
	};

	*ntests = DIM(testdata);

	return cbc_test_generic(ldr, "AES128", testdata, DIM(testdata));
}

static int cbc_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = cbc_test_blowfish(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	if ((tres = cbc_test_aes128(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static int cbc_fini(drew_mode_t *ctx, int flags)
{
	struct cbc *c = ctx->ctx;

	if (c->algo)
		c->algo->functbl->fini(c->algo, 0);
	memset(c->buf, 0, c->blksize);
	drew_mem_sfree(c->buf);
	memset(c->iv, 0, c->blksize);
	drew_mem_sfree(c->iv);
	memset(c, 0, sizeof(*c));
	if (!(flags & DREW_MODE_FIXED)) {
		drew_mem_free(c);
		ctx->ctx = NULL;
	}

	return 0;
}

static int cbc_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags)
{
	struct cbc *c = oldctx->ctx, *cn;
	if (!(flags & DREW_MODE_FIXED))
		newctx->ctx = drew_mem_malloc(sizeof(struct cbc));
	cn = newctx->ctx;
	memcpy(newctx->ctx, oldctx->ctx, sizeof(struct cbc));
	if (c->algo) {
		cn->algo = drew_mem_memdup(c->algo, sizeof(*cn->algo));
		cn->algo->functbl->clone(cn->algo, c->algo, 0);
	}
	if (c->buf)
		cn->buf = drew_mem_memdup(c->buf, c->blksize);
	if (c->iv)
		cn->iv = drew_mem_memdup(c->iv, c->blksize);
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "CBC", &cbc_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(cbc)(void *ldr, int op, int id, void *p)
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
