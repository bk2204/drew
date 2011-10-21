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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/mem.h>
#include <drew/mode.h>
#include <drew/block.h>
#include <drew/plugin.h>

#include "util.hh"

HIDE()
#define TABLE_SIZE (64 * 1024)

typedef BigEndian E;

extern "C" {

struct gcm;

struct gcm {
	const drew_loader_t *ldr;
	drew_block_t *algo;
	uint8_t y0[16] ALIGNED_T;
	uint8_t y[16] ALIGNED_T;
	uint8_t h[16] ALIGNED_T;
	uint8_t x[16] ALIGNED_T;
	uint8_t buf[16] ALIGNED_T;
	uint8_t cbuf[16] ALIGNED_T;
	uint8_t *iv;
	uint64_t *table;
	void (*mul)(struct gcm *, uint8_t *);
	size_t ivlen;
	size_t blksize;
	size_t boff;
	size_t alen;
	size_t clen;
	size_t taglen;
};

static int gcm_info(int op, void *p);
static int gcm_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int gcmfl_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int gcm_reset(drew_mode_t *ctx);
static int gcm_setpad(drew_mode_t *ctx, const drew_pad_t *pad);
static int gcm_setblock(drew_mode_t *ctx, const drew_block_t *algoctx);
static int gcm_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len);
static int gcm_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int gcm_encryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int gcm_decrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int gcm_decryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int gcm_fini(drew_mode_t *ctx, int flags);
static int gcm_test(void *p, const drew_loader_t *ldr);
static int gcm_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags);
static int gcm_setdata(drew_mode_t *, const uint8_t *, size_t);
static int gcm_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);
static int gcm_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);

/* The slow implementation. */
static const drew_mode_functbl_t gcm_functbl = {
	gcm_info, gcm_init, gcm_clone, gcm_reset, gcm_fini, gcm_setpad,
	gcm_setblock, gcm_setiv, gcm_encrypt, gcm_decrypt,
	gcm_encryptfast, gcm_decryptfast, gcm_setdata,
	gcm_encryptfinal, gcm_decryptfinal, gcm_test
};
/* The fastest implementation which uses large tables. */
static const drew_mode_functbl_t gcmfl_functbl = {
	gcm_info, gcmfl_init, gcm_clone, gcm_reset, gcm_fini, gcm_setpad,
	gcm_setblock, gcm_setiv, gcm_encrypt, gcm_decrypt,
	gcm_encryptfast, gcm_decryptfast, gcm_setdata,
	gcm_encryptfinal, gcm_decryptfinal, gcm_test
};

static int gcm_info(int op, void *p)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return 2;
		case DREW_MODE_INTSIZE:
			return sizeof(struct gcm);
		case DREW_MODE_FINAL_INSIZE:
		case DREW_MODE_FINAL_OUTSIZE:
			return 16;
		case DREW_MODE_QUANTUM:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int gcm_reset(drew_mode_t *ctx)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	int res = 0;

	if ((res = gcm_setiv(ctx, c->iv, c->ivlen)))
		return res;
	c->boff = 0;
	c->clen = 0;
	c->alen = 0;
	return 0;
}

static inline void mul(struct gcm *ctx, uint8_t *buf);
static inline void mul_fl(struct gcm *ctx, uint8_t *buf);
static void gen_table_fl(struct gcm *ctx);

static int gcm_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct gcm *newctx = (struct gcm *)ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = (struct gcm *)drew_mem_smalloc(sizeof(*newctx));
	memset(newctx, 0, sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->algo = NULL;
	newctx->boff = 0;
	newctx->taglen = 16;
	newctx->mul = mul;

	for (const drew_param_t *p = param; p; p = p->next)
		if (!strcmp(p->name, "tagLength"))
			newctx->taglen = p->param.number;

	ctx->ctx = newctx;
	ctx->functbl = &gcm_functbl;

	return 0;
}

static int gcmfl_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct gcm *newctx = (struct gcm *)ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = (struct gcm *)drew_mem_smalloc(sizeof(*newctx));
	memset(newctx, 0, sizeof(*newctx));
	newctx->table = (uint64_t *)drew_mem_smalloc(TABLE_SIZE);
	if (!newctx->table) {
		if (!(flags & DREW_MODE_FIXED))
			drew_mem_sfree(newctx);
		return -ENOMEM;
	}
	newctx->ldr = ldr;
	newctx->algo = NULL;
	newctx->boff = 0;
	newctx->taglen = 16;
	newctx->mul = mul_fl;

	for (const drew_param_t *p = param; p; p = p->next)
		if (!strcmp(p->name, "tagLength"))
			newctx->taglen = p->param.number;

	ctx->ctx = newctx;
	ctx->functbl = &gcmfl_functbl;

	return 0;
}

static int gcm_setpad(drew_mode_t *ctx, const drew_pad_t *algoname)
{
	return -DREW_ERR_NOT_ALLOWED;
}

static int gcm_setblock(drew_mode_t *ctx, const drew_block_t *algoctx)
{
	struct gcm *c = (struct gcm *)ctx->ctx;

	if (!algoctx)
		return DREW_ERR_INVALID;

	c->algo = (drew_block_t *)drew_mem_malloc(sizeof(*c->algo));
	c->algo->functbl = algoctx->functbl;
	c->algo->functbl->clone(c->algo, algoctx, 0);
	c->blksize = c->algo->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (c->blksize == 8)
		return -DREW_ERR_NOT_IMPL;
	if (c->blksize != 16)
		return -DREW_ERR_INVALID;
	memset(c->h, 0, sizeof(c->h));
	algoctx->functbl->encryptfast(algoctx, c->h, c->h, 1);

	if (c->mul == mul_fl)
		gen_table_fl(c);

	return 0;
}

static inline void mul(struct gcm *ctx, uint8_t *buf)
{
	uint64_t z[2] = {0, 0}, v[2];
	uint8_t *c = buf;
	const uint8_t *a = buf, *b = ctx->h;

	E::Copy(v, a, 16);
	for (int i = 0; i < 16; i++) {
		for (int j = 0x80; j != 0; j >>= 1) {
			int x = b[i] & j;
			z[0] ^= x ? v[0] : 0;
			z[1] ^= x ? v[1] : 0;
			x = v[1] & 1;
			v[1] = (v[1] >> 1) | (v[0] << 63);
			v[0] = (v[0] >> 1) ^ (x ? uint64_t(0xe1) << 56 : 0);
		}
	}
	E::Copy(c, z, 16);
}

/* The 64k table implementation is derived from Crypto++. */
static inline void mul_fl(struct gcm *ctx, uint8_t *buf)
{
	uint64_t x[2], a[2] ALIGNED_T = {0, 0};

	memcpy(x, buf, 16);
#define PTR_COMMON(a, c) (ctx->table+(a)*256*2+(c))
#if DREW_BYTE_ORDER == DREW_LITTLE_ENDIAN
#define RE(c, d) (d+4*(c%2))
#else
#define RE(c, d) (7-d-4*(c%2))
#endif
#define PTR_WORD(b, c, d) PTR_COMMON(c*4+d, (RE(c, d)?(x[b]>>((RE(c, d)?RE(c, d):1)*8-4))&0xff0:(x[b]&0xff)<<4)>>3)

	XorAligned(a, PTR_WORD(0, 0, 0), 16);
	XorAligned(a, PTR_WORD(0, 0, 1), 16);
	XorAligned(a, PTR_WORD(0, 0, 2), 16);
	XorAligned(a, PTR_WORD(0, 0, 3), 16);
	XorAligned(a, PTR_WORD(0, 1, 0), 16);
	XorAligned(a, PTR_WORD(0, 1, 1), 16);
	XorAligned(a, PTR_WORD(0, 1, 2), 16);
	XorAligned(a, PTR_WORD(0, 1, 3), 16);
	XorAligned(a, PTR_WORD(1, 2, 0), 16);
	XorAligned(a, PTR_WORD(1, 2, 1), 16);
	XorAligned(a, PTR_WORD(1, 2, 2), 16);
	XorAligned(a, PTR_WORD(1, 2, 3), 16);
	XorAligned(a, PTR_WORD(1, 3, 0), 16);
	XorAligned(a, PTR_WORD(1, 3, 1), 16);
	XorAligned(a, PTR_WORD(1, 3, 2), 16);
	XorAligned(a, PTR_WORD(1, 3, 3), 16);
	memcpy(buf, a, 16);
}

static void gen_table_fl(struct gcm *ctx)
{
	uint64_t v[2];
	uint64_t *table = ctx->table;

	E::Copy(v, ctx->h, 16);

	for (int i = 0; i < 128; i++) {
		int k = i & 7;
		uint8_t *stable = (uint8_t *)table;
		E::Copy(stable+(i/8)*256*16+(size_t(1)<<(11-k)), v, 16);

		int x = v[1] & 1;
		v[1] = (v[1] >> 1) | (v[0] << 63);
		v[0] = (v[0] >> 1) ^ (x ? uint64_t(0xe1) << 56 : 0);
	}

	for (int i = 0; i < 16; i++) {
		memset(table+i*256*2, 0, 16);
		for (int j = 2; j <= 0x80; j *= 2)
			for (int k = 1; k < j; k++)
				XorAligned(table+i*256*2+(j+k)*2, table+i*256*2+j*2,
						table+i*256*2+k*2, 16);
	}
}

// buf is aligned but block need not be.
static inline void hash(struct gcm *c, uint8_t *buf, const uint8_t *block)
{
	XorBuffers(buf, block, c->blksize);
	c->mul(c, buf);
}

static inline void hash_fast(struct gcm *c, uint8_t *buf, const uint8_t *block)
{
	XorAligned(buf, block, 16);
	c->mul(c, buf);
}

static int gcm_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;

	c->ivlen = len;
	if (iv != c->iv)
		c->iv = (uint8_t *)drew_mem_smemdup(iv, c->ivlen);
	if (len == 12) {
		memcpy(c->y0, c->iv, 12);
		memset(c->y0+12, 0, 3);
		c->y0[15] = 0x01;
	}
	else {
		uint64_t lenbuf[2] = {0x00};
		const uint8_t *data = iv;
		if (c->taglen != 16)
			return -DREW_ERR_INVALID;
		memset(c->y0, 0, sizeof(c->y0));
		for (size_t i = 0; i < (len / 16); i++, data += 16)
			hash(c, c->y0, data);
		if (len % 16) {
			memset(c->buf, 0, sizeof(c->buf));
			memcpy(c->buf, data, len % 16);
			hash(c, c->y0, c->buf);
		}
		lenbuf[1] = len << 3;
		E::Copy(c->buf, lenbuf, sizeof(c->buf));
		hash(c, c->y0, c->buf);
	}
	memcpy(c->y, c->y0, c->blksize);
	c->alen = c->clen = 0;

	return 0;
}

static void increment_counter(uint8_t *ctr, size_t len)
{
	bool carry = 0;
	carry = !++ctr[len - 1];
	for (size_t i = len - 2; carry && i >= len - 4; i--) {
		if (!(carry = !++ctr[i]))
			break;
	}
}

static int gcm_encrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	c->clen += len;

	if (c->boff) {
		const size_t b = std::min(c->blksize - c->boff, len);
		for (size_t i = 0; i < b; i++)
			out[i] = c->cbuf[c->boff + i] = c->buf[c->boff + i] ^ in[i];
		if ((c->boff += b) == c->blksize) {
			c->boff = 0;
			hash(c, c->x, c->cbuf);
		}
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->blksize) {
		increment_counter(c->y, c->blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		XorBuffers(out, c->buf, in, c->blksize);
		hash(c, c->x, out);
		len -= c->blksize;
		out += c->blksize;
		in += c->blksize;
	}

	if (len) {
		increment_counter(c->y, c->blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		for (size_t i = 0; i < len; i++)
			out[i] = c->cbuf[i] = c->buf[i] ^ in[i];
		c->boff = len;
	}

	return 0;
}

static int gcm_encryptfast(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;
	const size_t blksize = 16;

	c->clen += len;

	while (len >= blksize) {
		increment_counter(c->y, blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		XorAligned(out, c->buf, in, blksize);
		hash_fast(c, c->x, out);
		len -= blksize;
		out += blksize;
		in += blksize;
	}

	return 0;
}

static int gcm_decrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	c->clen += len;

	if (c->boff) {
		const size_t b = std::min(c->blksize - c->boff, len);
		for (size_t i = 0; i < b; i++)
			out[i] = c->buf[c->boff + i] ^ (c->cbuf[c->boff + i] = in[i]);
		if ((c->boff += b) == c->blksize) {
			c->boff = 0;
			hash(c, c->x, c->cbuf);
		}
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->blksize) {
		increment_counter(c->y, c->blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		hash(c, c->x, in);
		XorBuffers(out, c->buf, in, c->blksize);
		len -= c->blksize;
		out += c->blksize;
		in += c->blksize;
	}

	if (len) {
		increment_counter(c->y, c->blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		for (size_t i = 0; i < len; i++)
			out[i] = c->buf[i] ^ (c->cbuf[i] = in[i]);
		c->boff = len;
	}

	return 0;
}

static int gcm_decryptfast(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;
	const size_t blksize = 16;

	c->clen += len;

	while (len >= blksize) {
		increment_counter(c->y, blksize);
		c->algo->functbl->encrypt(c->algo, c->buf, c->y);
		hash_fast(c, c->x, in);
		XorAligned(out, c->buf, in, blksize);
		len -= blksize;
		out += blksize;
		in += blksize;
	}

	return 0;
}

static int gcm_setdata(drew_mode_t *ctx, const uint8_t *data, size_t len)
{
	struct gcm *c = (struct gcm *)ctx->ctx;

	memset(c->x, 0, 16);
	for (size_t i = 0; i < (len / 16); i++, data += 16)
		hash(c, c->x, data);
	/* Since setting data happens before encrypting, it's safe to simply reuse
	 * buf as a temporary buffer.
	 */
	memset(c->buf, 0, sizeof(c->buf));
	memcpy(c->buf, data, len & 15);
	hash(c, c->x, c->buf);
	c->alen = len;
	return 0;
}

static int gcm_encryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint64_t lenbuf[2];
	if (outlen < inlen + c->taglen)
		return -DREW_ERR_MORE_INFO;

	gcm_encrypt(ctx, out, in, inlen);

	if (c->boff) {
		const size_t b = c->blksize - c->boff;
		for (size_t i = 0; i < b; i++)
			c->cbuf[c->boff + i] = 0;
		hash(c, c->x, c->cbuf);
	}

	lenbuf[0] = c->alen << 3;
	lenbuf[1] = c->clen << 3;
	E::Copy(c->buf, lenbuf, sizeof(c->buf));
	hash(c, c->x, c->buf);
	c->algo->functbl->encrypt(c->algo, c->buf, c->y0);
	XorAligned(c->x, c->buf, c->blksize);
	memcpy(out+inlen, c->x, c->taglen);
	
	return outlen;
}

static int gcm_decryptfinal(drew_mode_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	struct gcm *c = (struct gcm *)ctx->ctx;
	uint64_t lenbuf[2];

	gcm_decrypt(ctx, out, in, outlen);

	if (c->boff) {
		const size_t b = c->blksize - c->boff;
		for (size_t i = 0; i < b; i++)
			c->cbuf[c->boff + i] = 0;
		hash(c, c->x, c->cbuf);
	}

	lenbuf[0] = c->alen << 3;
	lenbuf[1] = c->clen << 3;
	E::Copy(c->buf, lenbuf, sizeof(c->buf));
	hash(c, c->x, c->buf);
	c->algo->functbl->encrypt(c->algo, c->buf, c->y0);
	XorAligned(c->x, c->buf, c->blksize);
	return memcmp(in+outlen, c->x, c->taglen) ?
		-DREW_ERR_VERIFY_FAILED : outlen;
}

struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *iv;
	size_t ivsz;
	const uint8_t *aad;
	size_t aadsz;
	const uint8_t *input;
	size_t insz;
	const uint8_t *output;
	size_t outsz;
};

static int gcm_test_generic(const drew_loader_t *ldr, const char *name,
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
	functbl = (drew_block_functbl_t *)tmp;
	functbl->init(&algo, 0, ldr, NULL);

	for (size_t i = 0; i < ntests; i++) {
		memset(buf, 0, sizeof(buf));
		result <<= 1;

		gcm_init(&c, 0, ldr, NULL);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		gcm_setblock(&c, &algo);
		gcm_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		gcm_setdata(&c, testdata[i].aad, testdata[i].aadsz);
		for (size_t j = 0; j < testdata[i].insz; j += 9)
			gcm_encrypt(&c, buf+j, testdata[i].input+j,
					std::min<size_t>(9, testdata[i].insz - j));
		gcm_encryptfinal(&c, buf+testdata[i].insz, 16, NULL, 0);

		result |= !!memcmp(buf, testdata[i].output, testdata[i].outsz);
		gcm_fini(&c, 0);
		algo.functbl->fini(&algo, 0);

		result <<= 1;
		gcm_init(&c, 0, ldr, NULL);
		algo.functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		gcm_setblock(&c, &algo);
		gcm_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		gcm_setdata(&c, testdata[i].aad, testdata[i].aadsz);
		for (size_t j = 0; j < testdata[i].insz; j += 9)
			gcm_decrypt(&c, buf+j, testdata[i].output+j,
					std::min<size_t>(9, testdata[i].insz - j));
		result |= gcm_decryptfinal(&c, NULL, 0,
				testdata[i].output+testdata[i].insz, 16) < 0;
		result |= !!memcmp(buf, testdata[i].input, testdata[i].insz);
		gcm_fini(&c, 0);
		algo.functbl->fini(&algo, 0);
	}
	
	return result;
}

static int gcm_test_aes128(const drew_loader_t *ldr, size_t *ntests)
{
	const uint8_t *key = (const uint8_t *)"\xfe\xff\xe9\x92\x86\x65\x73\x1c"
		"\x6d\x6a\x8f\x94\x67\x30\x83\x08";
	const uint8_t *input = (const uint8_t *)"\xd9\x31\x32\x25\xf8\x84\x06\xe5"
		"\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
		"\x86\xa7\xa9\x53\x15\x34\xf7\xda"
		"\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
		"\x1c\x3c\x0c\x95\x95\x68\x09\x53"
		"\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
		"\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
		"\xba\x63\x7b\x39";
	const uint8_t *aad = (const uint8_t *)"\xfe\xed\xfa\xce\xde\xad\xbe\xef"
		"\xfe\xed\xfa\xce\xde\xad\xbe\xef"
		"\xab\xad\xda\xd2";
	struct test testdata[] = {
		{
			key,
			16,
			(const uint8_t *)"\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
			12,
			aad,
			20,
			input,
			60,
			(const uint8_t *)
				"\x42\x83\x1e\xc2\x21\x77\x74\x24"
				"\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
				"\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
				"\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
				"\x21\xd5\x14\xb2\x54\x66\x93\x1c"
				"\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
				"\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
				"\x3d\x58\xe0\x91\x5b\xc9\x4f\xbc"
				"\x32\x21\xa5\xdb\x94\xfa\xe9\x5a"
				"\xe7\x12\x1a\x47",
			76
		},
		{
			key,
			16,
			(const uint8_t *)
				"\x93\x13\x22\x5d\xf8\x84\x06\xe5"
				"\x55\x90\x9c\x5a\xff\x52\x69\xaa"
				"\x6a\x7a\x95\x38\x53\x4f\x7d\xa1"
				"\xe4\xc3\x03\xd2\xa3\x18\xa7\x28"
				"\xc3\xc0\xc9\x51\x56\x80\x95\x39"
				"\xfc\xf0\xe2\x42\x9a\x6b\x52\x54"
				"\x16\xae\xdb\xf5\xa0\xde\x6a\x57"
				"\xa6\x37\xb3\x9b",
			60,
			aad,
			20,
			input,
			60,
			(const uint8_t *)
				"\x8c\xe2\x49\x98\x62\x56\x15\xb6"
				"\x03\xa0\x33\xac\xa1\x3f\xb8\x94"
				"\xbe\x91\x12\xa5\xc3\xa2\x11\xa8"
				"\xba\x26\x2a\x3c\xca\x7e\x2c\xa7"
				"\x01\xe4\xa9\xa4\xfb\xa4\x3c\x90"
				"\xcc\xdc\xb2\x81\xd4\x8c\x7c\x6f"
				"\xd6\x28\x75\xd2\xac\xa4\x17\x03"
				"\x4c\x34\xae\xe5\x61\x9c\xc5\xae"
				"\xff\xfe\x0b\xfa\x46\x2a\xf4\x3c"
				"\x16\x99\xd0\x50",
			76
		}
	};


	*ntests = DIM(testdata);

	return gcm_test_generic(ldr, "AES128", testdata, DIM(testdata));
}

static int gcm_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = gcm_test_aes128(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static int gcm_fini(drew_mode_t *ctx, int flags)
{
	struct gcm *c = (struct gcm *)ctx->ctx;

	if (c->algo)
		c->algo->functbl->fini(c->algo, 0);
	drew_mem_free(c->algo);
	drew_mem_sfree(c->iv);
	drew_mem_sfree(c->table);
	if (!(flags & DREW_MODE_FIXED)) {
		drew_mem_sfree(c);
		ctx->ctx = NULL;
	}

	return 0;
}

static int gcm_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags)
{
	struct gcm *c = (struct gcm *)oldctx->ctx, *cn;

	if (!(flags & DREW_MODE_FIXED))
		newctx->ctx = (struct gcm *)drew_mem_smalloc(sizeof(struct gcm));
	memset(newctx->ctx, 0, sizeof(struct gcm));
	memcpy(newctx->ctx, oldctx->ctx, sizeof(struct gcm));
	cn = (struct gcm *)newctx->ctx;
	if (c->algo) {
		cn->algo = (drew_block_t *)drew_mem_memdup(c->algo, sizeof(*c->algo));
		cn->algo->functbl->clone(cn->algo, c->algo, 0);
	}
	if (c->table)
		cn->table = (uint64_t *)drew_mem_memdup(c->table, TABLE_SIZE);
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "GCM", &gcmfl_functbl },
	{ "GCM", &gcm_functbl },
};

EXPORT()
int DREW_PLUGIN_NAME(gcm)(void *ldr, int op, int id, void *p)
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
}
UNHIDE()
