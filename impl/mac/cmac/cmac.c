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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/block.h>
#include <drew/kdf.h>
#include <drew/mac.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

// This needs to be large enough to handle one block of the cipher.
#define BUFFER_SIZE 16

/* Interfaces must not modify the functbl member of the context since the KDF
 * implementation casts its context to the MAC implementation to avoid
 * duplicating lots of code needlessly.
 */

HIDE()
struct cmac {
	uint8_t buf[BUFFER_SIZE] ALIGNED_T;
	uint8_t hash[BUFFER_SIZE] ALIGNED_T;
	uint8_t k1[BUFFER_SIZE] ALIGNED_T;
	uint8_t k2[BUFFER_SIZE] ALIGNED_T;
	size_t blksize;
	size_t boff;
	size_t taglen;
	drew_block_t block;
	bool nonzero_len;
};

static int cmac_info(int op, void *p)
{
	if (op == DREW_MAC_VERSION)
		return CURRENT_ABI;
	return -DREW_ERR_NOT_IMPL;
}

static int cmac_info2(const drew_mac_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_MAC_VERSION:
			return CURRENT_ABI;
		case DREW_MAC_ENDIAN:
			return 0;
		case DREW_MAC_INTSIZE:
			return sizeof(struct cmac);
		case DREW_MAC_SIZE_CTX:
			if (ctx && ctx->ctx) {
				struct cmac *c = ctx->ctx;
				return c->taglen;
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_MAC_BLKSIZE_CTX:
			if (ctx && ctx->ctx) {
				struct cmac *c = ctx->ctx;
				return c->blksize;
			}
			return -DREW_ERR_MORE_INFO;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int cmac_init(drew_mac_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	drew_block_t *algo = NULL;
	size_t taglen = 0;

	for (; param; param = param->next) {
		if (!strcmp(param->name, "cipher"))
			algo = param->param.value;
		if (!strcmp(param->name, "tagLength"))
			taglen = param->param.number;
	}

	if (!algo)
		return -DREW_ERR_INVALID;

	struct cmac *p = drew_mem_smalloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	memset(p, 0, sizeof(*p));
	p->block.functbl = algo->functbl;
	p->blksize = p->block.functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	p->boff = 0;
	p->block.functbl->clone(&p->block, algo, 0);
	p->block.functbl->reset(&p->block);
	p->nonzero_len = false;
	p->taglen = taglen ? taglen : p->blksize;

	if (p->blksize > sizeof(p->k1) || p->blksize > sizeof(p->k2) ||
			(p->blksize != 8 && p->blksize != 16)) {
		drew_mem_sfree(p);
		return -DREW_ERR_INVALID;
	}

	if (flags & DREW_MAC_FIXED) {
		memcpy(ctx->ctx, p, sizeof(*p));
		drew_mem_sfree(p);
	}
	else
		ctx->ctx = p;
	return 0;
}

static int cmac_clone(drew_mac_t *newctx, const drew_mac_t *oldctx, int flags)
{
	struct cmac *h, *oh;
	if (!(flags & DREW_MAC_FIXED)) {
		newctx->ctx = drew_mem_smalloc(sizeof(*h));
	}
	memcpy(newctx->ctx, oldctx->ctx, sizeof(*h));
	h = newctx->ctx;
	oh = oldctx->ctx;

	h->block.functbl = oh->block.functbl;
	h->block.functbl->clone(&h->block, &oh->block, 0);

	return 0;
}

static int cmac_fini(drew_mac_t *ctx, int flags)
{
	struct cmac *h = ctx->ctx;
	h->block.functbl->fini(&h->block, 0);

	if (!(flags & DREW_MAC_FIXED)) {
		drew_mem_sfree(h);
		ctx->ctx = NULL;
	}
	return 0;
}

static void shiftleft(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len-1; i++) {
		buf[i] <<= 1;
		buf[i] |= (buf[i+1] >> 7);
	}
	buf[len-1] <<= 1;
}

static int cmac_setkey(drew_mac_t *ctxt, const uint8_t *data, size_t len)
{
	struct cmac *ctx = ctxt->ctx;
	uint8_t buf[BUFFER_SIZE] = {0};
	uint8_t c;
	uint8_t rb = (ctx->blksize == 16) ? 0x87 : 0x1b;

	ctx->block.functbl->setkey(&ctx->block, data, len, 0);
	ctx->block.functbl->encrypt(&ctx->block, ctx->k1, buf);
	c = ctx->k1[0];
	shiftleft(ctx->k1, ctx->blksize);
	if (c & 0x80)
		ctx->k1[ctx->blksize-1] ^= rb;
	memcpy(ctx->k2, ctx->k1, ctx->blksize);
	shiftleft(ctx->k2, ctx->blksize);
	if (c & 0x40)
		ctx->k2[ctx->blksize-1] ^= rb;

	return 0;
}

static int cmac_reset(drew_mac_t *ctx)
{
	int res = 0;
	struct cmac *c = ctx->ctx;
	if (c->block.ctx)
		c->block.functbl->reset(&c->block);
	c->boff = 0;
	c->nonzero_len = false;
	memset(c->hash, 0, sizeof(c->hash));
	return res;
}

static inline void process_block(struct cmac *c, const uint8_t *buf)
{
	xor_buffers2(c->hash, buf, c->blksize);
	c->block.functbl->encrypt(&c->block, c->hash, c->hash);
}

static int cmac_update(drew_mac_t *ctx, const uint8_t *data, size_t len)
{
	struct cmac *c = ctx->ctx;
	const uint8_t *in = data;

	if (len == 0)
		return 0;

	c->nonzero_len = true;

	if (c->boff) {
		const size_t b = MIN(c->blksize - c->boff, len);
		memcpy(c->buf+c->boff, in, b);
		if ((c->boff += b) == c->blksize) {
			if (len != b) {
				process_block(c, c->buf);
				c->boff = 0;
			}
			else
				c->boff = 16;
		}
		len -= b;
		in += b;
	}

	/* The last block must be treated specially, so make sure that this isn't it
	 * by ensuring that there's at least one more byte than the block size.
	 */
	while (len >= c->blksize+1) {
		process_block(c, in);
		len -= c->blksize;
		in += c->blksize;
	}

	if (len) {
		memcpy(c->buf, in, len);
		c->boff = len;
	}

	return 0;
}

static int cmac_final(drew_mac_t *ctx, uint8_t *digest, int flags)
{
	struct cmac *c = ctx->ctx;

	if (!c->nonzero_len) {
		memset(c->buf+1, 0, c->blksize-1);
		c->buf[c->boff] = 0x80;
		xor_aligned2(c->buf, c->k2, BUFFER_SIZE);
	}
	else if (c->boff == c->blksize) {
		xor_aligned2(c->buf, c->k1, BUFFER_SIZE);
	}
	else {
		memset(c->buf+c->boff, 0, c->blksize-c->boff);
		c->buf[c->boff] = 0x80;
		xor_aligned2(c->buf, c->k2, BUFFER_SIZE);
	}
	process_block(c, c->buf);
	memcpy(digest, c->hash, c->taglen);

	return 0;
}

struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *data;
	size_t datasz;
	size_t datarep;
	const uint8_t *output;
};

static int cmac_test_generic(DrewLoader *ldr, const char *name,
		const struct test *testdata, size_t ntests, size_t outputsz)
{
	int result = 0;
	drew_mac_t c;
	uint8_t buf[BUFFER_SIZE];
	drew_param_t param;
	drew_block_t block;
	int id;

	if ((id = drew_loader_lookup_by_name(ldr, name, 0, -1)) < 0)
		return id;
	drew_loader_get_functbl(ldr, id, (const void **)&block.functbl);

	block.functbl->init(&block, 0, ldr, NULL);

	param.name = "cipher";
	param.next = NULL;
	param.param.value = &block;

	for (size_t i = 0; i < ntests; i++) {
		const struct test *t = testdata + i;
		int retval;

		memset(buf, 0, sizeof(buf));
		result <<= 1;

		if ((retval = cmac_init(&c, 0, ldr, &param)))
			return retval;			
		cmac_setkey(&c, t->key, t->keysz);
		for (size_t j = 0; j < t->datarep; j++)
			for (size_t k = 0; k < t->datasz; k += 9)
				cmac_update(&c, t->data+k, MIN(9, t->datasz-k));
		cmac_final(&c, buf, 0);

		result |= !!memcmp(buf, t->output, outputsz);
		cmac_fini(&c, 0);
	}
	block.functbl->fini(&block, 0);
	
	return result;
}

#define U8P (const uint8_t *)
#define AES128_KEY U8P "\x2b\x7e\x15\x16\x28\xae\xd2\xa6" \
	"\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
static const struct test testdata_aes128[] = {
	{
		AES128_KEY,
		16,
		U8P "",
		0,
		1,
		U8P "\xbb\x1d\x69\x29\xe9\x59\x37\x28"
			"\x7f\xa3\x7d\x12\x9b\x75\x67\x46"
	},
	{
		AES128_KEY,
		16,
		U8P "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
			"\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
		16,
		1,
		U8P "\x07\x0a\x16\xb4\x6b\x4d\x41\x44"
			"\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c"
	},
	{
		AES128_KEY,
		16,
		U8P "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
			"\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
			"\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
			"\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
			"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
		40,
		1,
		U8P "\xdf\xa6\x67\x47\xde\x9a\xe6\x30"
			"\x30\xca\x32\x61\x14\x97\xc8\x27"
	}
};

static int cmac_test_aes128(DrewLoader *ldr, size_t *ntests)
{
	*ntests = DIM(testdata_aes128);

	return cmac_test_generic(ldr, "AES128", testdata_aes128,
			DIM(testdata_aes128), 16);
}

static int cmac_test(void *p, DrewLoader *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = cmac_test_aes128(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

#if 0
#define MAC(x) ((drew_mac_t *)(x))

int cmack_info(int op, void *p)
{
	drew_kdf_t *kdf = p;
	struct cmac *ctx;
	int hop = DREW_HASH_BLKSIZE;
	switch (op) {
		case DREW_KDF_VERSION:
			return 2;
		case DREW_KDF_SIZE:
			hop = DREW_HASH_SIZE;
		case DREW_KDF_BLKSIZE:
			if (!p)
				return -DREW_ERR_MORE_INFO;
			ctx = kdf->ctx;
			return ctx->outside.functbl->info(hop, &ctx->outside);
		case DREW_KDF_ENDIAN:
			return 0;
		case DREW_KDF_INTSIZE:
			return sizeof(struct cmac);
	}
	return -DREW_ERR_INVALID;
}

int cmack_init(drew_kdf_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	return cmac_init(MAC(ctx), flags, ldr, param);
}

int cmack_clone(drew_kdf_t *new, const drew_kdf_t *old, int flags)
{
	return cmac_clone(MAC(new), MAC(old), flags);
}

int cmack_reset(drew_kdf_t *ctx)
{
	return cmac_reset(MAC(ctx));
}

int cmack_fini(drew_kdf_t *ctx, int flags)
{
	return cmac_fini(MAC(ctx), flags);
}

int cmack_setkey(drew_kdf_t *ctx, const uint8_t *key, size_t len)
{
	return cmac_setkey(MAC(ctx), key, len);
}

int cmack_setsalt(drew_kdf_t *ctx, const uint8_t *salt, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

int cmack_setcount(drew_kdf_t *ctx, size_t count)
{
	return -DREW_ERR_NOT_ALLOWED;
}

int cmack_generate(drew_kdf_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	struct cmac *h = ctx->ctx;
	uint8_t buf[BUFFER_SIZE];

	if (outlen > h->digestsz)
		return -DREW_ERR_INVALID;

	cmac_update(MAC(ctx), in, inlen);
	if (outlen == h->digestsz)
		cmac_final(MAC(ctx), out, 0);
	else {
		cmac_final(MAC(ctx), buf, 0);
		memcpy(out, buf, outlen);
		memset(buf, 0, sizeof(buf));
	}

	return 0;
}

static int cmack_test_generic(DrewLoader *ldr, const char *name,
		const struct test *testdata, size_t ntests, size_t outputsz)
{
	int result = 0;
	drew_kdf_t c;
	uint8_t buf[BUFFER_SIZE];
	drew_param_t param;
	drew_hash_t hash;
	int id;

	if ((id = drew_loader_lookup_by_name(ldr, name, 0, -1)) < 0)
		return id;
	drew_loader_get_functbl(ldr, id, (const void **)&hash.functbl);

	hash.functbl->init(&hash, 0, ldr, NULL);

	param.name = "digest";
	param.next = NULL;
	param.param.value = &hash;

	for (size_t i = 0; i < ntests; i++) {
		const struct test *t = testdata + i;
		int retval;

		memset(buf, 0, sizeof(buf));
		result <<= 1;

		if (t->datarep != 1)
			continue;

		hash.functbl->reset(&hash);
		if ((retval = cmack_init(&c, 0, ldr, &param)))
			return retval;			
		cmack_setkey(&c, t->key, t->keysz);
		cmack_generate(&c, buf, outputsz, t->data, t->datasz);

		result |= !!memcmp(buf, t->output, outputsz);
		cmack_fini(&c, 0);
	}
	hash.functbl->fini(&hash, 0);
	
	return result;
}

static int cmack_test_md5(DrewLoader *ldr, size_t *ntests)
{
	*ntests = DIM(testdata_md5);

	return cmack_test_generic(ldr, "MD5", testdata_md5, DIM(testdata_md5), 16);
}

static int cmack_test(void *p, DrewLoader *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = cmack_test_md5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}
#endif

static drew_mac_functbl_t cmac_functbl = {
	cmac_info, cmac_info2, cmac_init, cmac_clone, cmac_reset, cmac_fini,
	cmac_setkey, cmac_update, cmac_update, cmac_final, cmac_test
};

#if 0
static drew_kdf_functbl_t cmack_functbl = {
	cmack_info, cmack_init, cmack_clone, cmack_reset, cmack_fini, cmack_setkey,
	cmack_setsalt, cmack_setcount, cmack_generate, cmack_test
};
#endif

struct plugin {
	const char *name;
	const void *functbl;
	size_t functblsz;
	int type;
};

static struct plugin plugin_data[] = {
	{ "CMAC", &cmac_functbl, sizeof(drew_mac_functbl_t), DREW_TYPE_MAC },
};

EXPORT()
int DREW_PLUGIN_NAME(cmac)(void *ldr, int op, int id, void *p)
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
			return plugin_data[id].type;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return plugin_data[id].functblsz;
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, plugin_data[id].functblsz);
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
UNHIDE()
