/*-
 * Copyright © 2010–2011 brian m. carlson
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

struct cfb {
	const drew_loader_t *ldr;
	size_t feedback;
	const drew_block_t *algo;
	uint8_t buf[32] ALIGNED_T;
	uint8_t prev[32] ALIGNED_T;
	uint8_t *iv;
	size_t blksize;
	size_t boff;
	size_t chunks;
};

static int cfb_info(int op, void *p);
static int cfb_info2(const drew_mode_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in);
static int cfb_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int cfb_reset(drew_mode_t *ctx);
static int cfb_resync(drew_mode_t *ctx);
static int cfb_setblock(drew_mode_t *ctx, const drew_block_t *algoctx);
static int cfb_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len);
static int cfb_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cfb_decrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cfb_encryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cfb_decryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int cfb_fini(drew_mode_t *ctx, int flags);
static int cfb_test(void *p, const drew_loader_t *ldr);
static int cfb_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags);
static int cfb_setdata(drew_mode_t *, const uint8_t *, size_t);
static int cfb_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);
static int cfb_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);

static const drew_mode_functbl_t cfb_functbl = {
	cfb_info, cfb_info2, cfb_init, cfb_clone, cfb_reset, cfb_fini,
	cfb_setblock, cfb_setiv, cfb_encrypt, cfb_decrypt, cfb_encrypt, cfb_decrypt,
	cfb_setdata, cfb_encryptfinal, cfb_decryptfinal, cfb_resync, cfb_test
};

static const drew_mode_functbl_t cfb_functblfast = {
	cfb_info, cfb_info2, cfb_init, cfb_clone, cfb_reset, cfb_fini,
	cfb_setblock, cfb_setiv, cfb_encrypt, cfb_decrypt,
	cfb_encryptfast, cfb_decryptfast, cfb_setdata,
	cfb_encryptfinal, cfb_decryptfinal, cfb_resync, cfb_test
};

static int cfb_info(int op, void *p)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct cfb);
		case DREW_MODE_FINAL_INSIZE:
		case DREW_MODE_FINAL_OUTSIZE:
			return 0;
		case DREW_MODE_QUANTUM:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int cfb_info2(const drew_mode_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return CURRENT_ABI;
		case DREW_MODE_INTSIZE:
			return sizeof(struct cfb);
		case DREW_MODE_FINAL_INSIZE_CTX:
		case DREW_MODE_FINAL_OUTSIZE_CTX:
			return 0;
		case DREW_MODE_BLKSIZE_CTX:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int cfb_resync(drew_mode_t *ctx)
{
	return -DREW_ERR_NOT_IMPL;
}

static int cfb_reset(drew_mode_t *ctx)
{
	struct cfb *c = ctx->ctx;
	int res = 0;

	if ((res = cfb_setiv(ctx, c->iv, c->blksize)))
		return res;
	c->boff = 0;
	return 0;
}

static int cfb_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct cfb *newctx = ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = drew_mem_smalloc(sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->feedback = 0;
	newctx->algo = NULL;
	newctx->boff = 0;
	
	for (; param; param = param->next)
		if (!strcmp(param->name, "feedbackBits")) {
			newctx->feedback = param->param.number / 8;
			break;
		}

	ctx->ctx = newctx;
	ctx->functbl = &cfb_functbl;

	return 0;
}

static int cfb_setblock(drew_mode_t *ctx, const drew_block_t *algoctx)
{
	struct cfb *c = ctx->ctx;

	/* You really do need to pass something for the algoctx parameter, because
	 * otherwise you haven't set a key for the algorithm.  That's a bit bizarre,
	 * but we might allow it in the future (such as for PRNGs).
	 */
	if (!algoctx)
		return DREW_ERR_INVALID;

	c->algo = algoctx;
	c->blksize = c->algo->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (!c->feedback)
		c->feedback = c->blksize;
	if (c->feedback == c->blksize && (c->blksize == 8 || c->blksize == 16)) {
		c->chunks = DREW_MODE_ALIGNMENT / c->blksize;
		ctx->functbl = &cfb_functblfast;
	}
	if (!(c->iv = drew_mem_smalloc(c->blksize)))
		return -ENOMEM;

	return 0;
}

static int cfb_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len)
{
	struct cfb *c = ctx->ctx;

	if (c->blksize != len)
		return -EINVAL;

	memcpy(c->prev, iv, len);
	memcpy(c->buf, iv, len);
	if (iv != c->iv)
		memcpy(c->iv, iv, len);
	return 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static int cfb_encrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct cfb *c = ctx->ctx;
	const size_t leftover = c->blksize - c->feedback;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	if (c->boff) {
		const size_t b = MIN(c->feedback - c->boff, len);
		for (size_t i = 0; i < b; i++)
			c->prev[leftover + c->boff + i] = out[i] =
				c->buf[c->boff + i] ^= in[i];
		if ((c->boff += b) == c->feedback)
			c->boff = 0;
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->feedback) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->prev);
		memmove(c->prev, c->prev + c->feedback, leftover);
		for (size_t i = 0; i < c->feedback; i++)
			c->prev[i + leftover] = out[i] = c->buf[i] ^= in[i];
		len -= c->feedback;
		out += c->feedback;
		in += c->feedback;
	}

	if (len) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->prev);
		memmove(c->prev, c->prev + c->feedback, leftover);
		for (size_t i = 0; i < len; i++)
			c->prev[i + leftover] = out[i] = c->buf[i] ^= in[i];
		c->boff = len;
	}

	return 0;
}

static int cfb_decrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct cfb *c = ctx->ctx;
	const size_t leftover = c->blksize - c->feedback;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	if (c->boff) {
		const size_t b = MIN(c->feedback - c->boff, len);
		for (size_t i = 0; i < b; i++)
			out[i] = c->buf[c->boff + i] ^
				(c->prev[leftover + c->boff + i] = in[i]);
		c->boff -= b;
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->feedback) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->prev);
		memmove(c->prev, c->prev + c->feedback, leftover);
		for (size_t i = 0; i < c->feedback; i++)
			out[i] = c->buf[i] ^ (c->prev[i + leftover] = in[i]);
		len -= c->feedback;
		out += c->feedback;
		in += c->feedback;
	}

	if (len) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->prev);
		memmove(c->prev, c->prev + c->feedback, leftover);
		for (size_t i = 0; i < len; i++)
			out[i] = c->buf[i] ^ (c->prev[i + leftover] = in[i]);
		c->boff = len;
	}

	return 0;
}


struct aligned {
	uint8_t data[DREW_MODE_ALIGNMENT] ALIGNED_T;
};

static int cfb_encryptfast(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct cfb *c = ctx->ctx;
	struct aligned *cur = (struct aligned *)c->prev;
	struct aligned *out = (struct aligned *)outp;
	const struct aligned *in = (const struct aligned *)inp;

	len /= DREW_MODE_ALIGNMENT;

	for (size_t j = 0; j < len; j++, out++, in++) {
		c->algo->functbl->encryptfast(c->algo, c->buf, cur->data, c->chunks);
		xor_aligned(out->data, c->buf, in->data, DREW_MODE_ALIGNMENT);
		cur = out;
	}
	memcpy(c->prev, cur, DREW_MODE_ALIGNMENT);

	return 0;
}

static int cfb_decryptfast(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct cfb *c = ctx->ctx;
	struct aligned *out = (struct aligned *)outp;
	const struct aligned *cur = (const struct aligned *)c->prev;
	const struct aligned *in = (const struct aligned *)inp;

	len /= DREW_MODE_ALIGNMENT;

	for (size_t j = 0; j < len; j++, out++, in++) {
		c->algo->functbl->encryptfast(c->algo, c->buf, cur->data, c->chunks);
		xor_aligned(out->data, c->buf, in->data, DREW_MODE_ALIGNMENT);
		cur = in;
	}
	memcpy(c->prev, cur, DREW_MODE_ALIGNMENT);

	return 0;
}

static int cfb_setdata(drew_mode_t *ctx, const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

static int cfb_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	cfb_encrypt(ctx, out, in, inlen);
	return inlen;
}

static int cfb_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	cfb_decrypt(ctx, out, in, inlen);
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

static int cfb_test_generic(const drew_loader_t *ldr, const char *name,
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
		cfb_init(&c, 0, ldr, &param);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		cfb_setblock(&c, &algo);
		cfb_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		/* We use 9 here because it tests all three code paths for 64-bit
		 * blocks.
		 */
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			cfb_encrypt(&c, buf+j, testdata[i].input+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].output, testdata[i].datasz);
		cfb_fini(&c, 0);
		algo.functbl->fini(&algo, 0);

		cfb_init(&c, 0, ldr, &param);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		cfb_setblock(&c, &algo);
		cfb_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			cfb_decrypt(&c, buf+j, testdata[i].output+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].input, testdata[i].datasz);
		cfb_fini(&c, 0);
		algo.functbl->fini(&algo, 0);
	}
	
	return result;
}

static int cfb_test_cast5(const drew_loader_t *ldr, size_t *ntests)
{
	uint8_t buf[8];
	struct test testdata[] = {
		{
			(const uint8_t *)"\x01\x23\x45\x67\x12\x34\x56\x78"
				"\x23\x45\x67\x89\x34\x56\x78\x9a",
			16,
			buf,
			8,
			(const uint8_t *)"\x01\x23\x45\x67\x89\xab\xcd\xef",
			(const uint8_t *)"\x34\xf2\x64\x83\x3a\x2e\x07\x5d",
			8,
			8
		},
		{
			(const uint8_t *)"\xfe\xdc\xba\x98\x76\x54\x32\x10"
				"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
			16,
			(const uint8_t *)"\x01\x23\x45\x67\x12\x34\x56\x78",
			8,
			(const uint8_t *)"This is CAST5/CFB.",
			(const uint8_t *)"\x2c\xfc\xe2\xf4\x55\xe3\x8d\x7f"
				"\x24\xbd\x0d\x94\x2f\x3c\xe8\x19\x06\x1d",
			18,
			8
		},
	};

	memset(buf, 0, sizeof(buf));
	*ntests = DIM(testdata);

	return cfb_test_generic(ldr, "CAST-128", testdata, DIM(testdata));
}

static int cfb_test_blowfish(const drew_loader_t *ldr, size_t *ntests)
{
	struct test testdata[] = {
		{
			(const uint8_t *)"\x01\x23\x45\x67\x89\xab\xcd\xef"
				"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
			16,
			(const uint8_t *)"\xfe\xdc\xba\x98\x76\x54\x32\x10",
			8,
			(const uint8_t *)"7654321 Now is the time for ",
			(const uint8_t *)"\xe7\x32\x14\xa2\x82\x21\x39\xca"
				"\xf2\x6e\xcf\x6d\x2e\xb9\xe7\x6e"
				"\x3d\xa3\xde\x04\xd1\x51\x72\x00"
				"\x51\x9d\x57\xa6\xc3",
			29,
			8
		}
	};

	*ntests = DIM(testdata);

	return cfb_test_generic(ldr, "Blowfish", testdata, DIM(testdata));
}

static int cfb_test_aes128(const drew_loader_t *ldr, size_t *ntests)
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
				"\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d",
			(const uint8_t *)
				"\x3b\x79\x42\x4c\x9c\x0d\xd4\x36"
				"\xba\xce\x9e\x0e\xd4\x58\x6a\x4f\x32\xb9",
			18,
			1
		}
	};

	*ntests = DIM(testdata);

	return cfb_test_generic(ldr, "AES128", testdata, DIM(testdata));
}

static int cfb_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -EINVAL;

	if ((tres = cfb_test_cast5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	if ((tres = cfb_test_blowfish(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	if ((tres = cfb_test_aes128(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static int cfb_fini(drew_mode_t *ctx, int flags)
{
	struct cfb *c = ctx->ctx;

	drew_mem_sfree(c->iv);
	if (flags & DREW_MODE_FIXED) {
		memset(c->buf, 0, sizeof(c->buf));
		memset(c->prev, 0, sizeof(c->prev));
	}
	else {
		drew_mem_sfree(c);
		ctx->ctx = NULL;
	}

	return 0;
}

static int cfb_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags)
{
	if (!(flags & DREW_MODE_FIXED))
		newctx->ctx = drew_mem_malloc(sizeof(struct cfb));
	memcpy(newctx->ctx, oldctx->ctx, sizeof(struct cfb));
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "CFB", &cfb_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(cfb)(void *ldr, int op, int id, void *p)
{
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]);

	if (id < 0 || id >= nplugins)
		return -EINVAL;

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
			return -EINVAL;
	}
}
UNEXPORT()
