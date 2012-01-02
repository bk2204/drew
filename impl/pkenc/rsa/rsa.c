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
#include "util.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/bignum.h>
#include <drew/mem.h>
#include <drew/pkenc.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct rsa {
	drew_bignum_t *p;
	drew_bignum_t *q;
	drew_bignum_t *u;
	drew_bignum_t *e;
	drew_bignum_t *d;
	drew_bignum_t *n;
};

static int rsa_info(int op, void *p);
static int rsa_info2(const drew_pkenc_t *, int, drew_param_t *,
		const drew_param_t *);
static int rsa_init(drew_pkenc_t *, int,
		const drew_loader_t *, const drew_param_t *);
static int rsa_clone(drew_pkenc_t *, const drew_pkenc_t *, int);
static int rsa_fini(drew_pkenc_t *, int);
static int rsa_generate(drew_pkenc_t *, const drew_param_t *);
static int rsa_setmode(drew_pkenc_t *, int);
static int rsa_setval(drew_pkenc_t *, const char *, const uint8_t *, size_t);
static int rsa_val(const drew_pkenc_t *, const char *, uint8_t *, size_t);
static int rsa_valsize(const drew_pkenc_t *, const char *);
static int rsa_encrypt(const drew_pkenc_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_decrypt(const drew_pkenc_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_test(void *, const drew_loader_t *);


static const drew_pkenc_functbl_t rsa_functbl = {
	.info = rsa_info,
	.info2 = rsa_info2,
	.init = rsa_init,
	.clone = rsa_clone,
	.fini = rsa_fini,
	.generate = rsa_generate,
	.setmode = rsa_setmode,
	.setval = rsa_setval,
	.val = rsa_val,
	.valsize = rsa_valsize,
	.encrypt = rsa_encrypt,
	.decrypt = rsa_decrypt,
	.test = rsa_test
};

#include "../../multi/rsa/rsa.c"

static int rsa_info(int op, void *p)
{
	drew_param_t *param = p;
	switch (op) {
		case DREW_PKENC_VERSION:
			return CURRENT_ABI;
		case DREW_PKENC_INTSIZE:
			return sizeof(struct rsa);
		case DREW_PKENC_DECRYPT_IN:
			return DIM(dec_in);
		case DREW_PKENC_DECRYPT_OUT:
			return DIM(dec_out);
		case DREW_PKENC_ENCRYPT_IN:
			return DIM(enc_in);
		case DREW_PKENC_ENCRYPT_OUT:
			return DIM(enc_out);
		case DREW_PKENC_DECRYPT_IN_NAME_TO_INDEX:
			return name_to_index(param, DIM(dec_in), dec_in);
		case DREW_PKENC_DECRYPT_IN_INDEX_TO_NAME:
			return index_to_name(param, DIM(dec_in), dec_in);
		case DREW_PKENC_DECRYPT_OUT_NAME_TO_INDEX:
			return name_to_index(param, DIM(dec_out), dec_out);
		case DREW_PKENC_DECRYPT_OUT_INDEX_TO_NAME:
			return index_to_name(param, DIM(dec_out), dec_out);
		case DREW_PKENC_ENCRYPT_IN_NAME_TO_INDEX:
			return name_to_index(param, DIM(enc_in), enc_in);
		case DREW_PKENC_ENCRYPT_IN_INDEX_TO_NAME:
			return index_to_name(param, DIM(enc_in), enc_in);
		case DREW_PKENC_ENCRYPT_OUT_NAME_TO_INDEX:
			return name_to_index(param, DIM(enc_out), enc_out);
		case DREW_PKENC_ENCRYPT_OUT_INDEX_TO_NAME:
			return index_to_name(param, DIM(enc_out), enc_out);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int rsa_info2(const drew_pkenc_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_PKENC_VERSION:
			return CURRENT_ABI;
		case DREW_PKENC_INTSIZE:
			return sizeof(struct rsa);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int rsa_test(void *ptr, const drew_loader_t *ldr)
{
	uint8_t p[] = {0x3d}, q[] = {0x35}, n[] = {0x0c, 0xa1}, e[] = {0x11},
			d[] = {0x0a, 0xc1}, m[] = {0x41}, c[] = {0x0a, 0xe6};
	uint8_t buf[2];
	const void *functbl;
	drew_pkenc_t ctx;
	int res = 0, id;
	drew_param_t param;
	const char *bignum = "Bignum";
	drew_bignum_t bns[1];

	id = drew_loader_lookup_by_name(ldr, bignum, 0, -1);
	if (id < 0)
		return id;
	if (drew_loader_get_type(ldr, id) != DREW_TYPE_BIGNUM)
		return -DREW_ERR_INVALID;
	if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
		return res;

	param.next = NULL;
	param.name = "bignum";
	param.param.value = bns;

	res = 0;

	bns[0].functbl = functbl;
	bns[0].functbl->init(&bns[0], 0, ldr, NULL);

	ctx.functbl = &rsa_functbl;
	if (ctx.functbl->init(&ctx, 0, ldr, &param) != 0)
		return 3;
	ctx.functbl->setval(&ctx, "p", p, DIM(p));
	ctx.functbl->setval(&ctx, "q", q, DIM(q));
	ctx.functbl->setval(&ctx, "n", n, DIM(n));
	ctx.functbl->setval(&ctx, "e", e, DIM(e));
	ctx.functbl->setval(&ctx, "d", d, DIM(d));
	bns[0].functbl->setbytes(&bns[0], m, sizeof(m));
	ctx.functbl->encrypt(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res |= !!memcmp(buf, c, sizeof(c));
	bns[0].functbl->setbytes(&bns[0], c, sizeof(c));
	ctx.functbl->decrypt(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res <<= 1;
	res |= !!memcmp(buf, m, sizeof(m));
	ctx.functbl->fini(&ctx, 0);
	bns[0].functbl->fini(&bns[0], 0);

	return res;
}

static int rsa_init(drew_pkenc_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct rsa *newctx = ctx->ctx;
	int res = 0;

	if (!(flags & DREW_PKENC_FIXED))
		newctx = drew_mem_malloc(sizeof(*newctx));

	if ((res = init(newctx, flags, ldr, param)))
		return res;
	
	ctx->ctx = newctx;
	ctx->functbl = &rsa_functbl;

	return 0;
}

static int rsa_fini(drew_pkenc_t *ctx, int flags)
{
	struct rsa *c = ctx->ctx;

	fini(c, flags);
	if (!(flags & DREW_PKENC_FIXED))
		drew_mem_free(c);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int rsa_clone(drew_pkenc_t *newctx, const drew_pkenc_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKENC_FIXED))
		newctx->ctx = drew_mem_malloc(sizeof(struct rsa));

	memset(newctx->ctx, 0, sizeof(struct rsa));

	struct rsa *new = newctx->ctx, *old = oldctx->ctx;
	CLONE(new, old, p);
	CLONE(new, old, q);
	CLONE(new, old, u);
	CLONE(new, old, e);
	CLONE(new, old, d);
	CLONE(new, old, n);
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int rsa_generate(drew_pkenc_t *ctx, const drew_param_t *param)
{
	return -DREW_ERR_NOT_IMPL;
}

static int rsa_setmode(drew_pkenc_t *ctx, int flags)
{
	return 0;
}

static int rsa_setval(drew_pkenc_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return setval(c, name, buf, len);
}

static int rsa_val(const drew_pkenc_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return val(c, name, data, len);
}

static int rsa_valsize(const drew_pkenc_t *ctx, const char *name)
{
	struct rsa *c = ctx->ctx;
	return valsize(c, name);
}

static int rsa_encrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return encrypt(c, out, in);
}

static int rsa_decrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return decrypt(c, out, in);
}

struct plugin {
	const char *name;
	const drew_pkenc_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "RSAEncryption", &rsa_functbl },
};

EXPORT()
int DREW_PLUGIN_NAME(rsa)(void *ldr, int op, int id, void *p)
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
			return DREW_TYPE_PKENC;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_pkenc_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_pkenc_functbl_t));
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
