/*-
 * Copyright © 2011–2012 brian m. carlson
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/kdf.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

/* This needs to be large enough to handle the output size of the underlying
 * PRF (usually that of the hash algorithm used in the HMAC instance).
 */
#define BUFFER_SIZE		256

HIDE()
struct tls {
	DrewLoader *ldr;
	drew_kdf_t prf;
	size_t prfsz;
};

static int tls_info(int op, void *p);
static int tls_info2(const drew_kdf_t *kdf, int op, drew_param_t *out,
		const drew_param_t *in);
static int tls_init(drew_kdf_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param);
static int tls_clone(drew_kdf_t *new, const drew_kdf_t *old, int flags);
static int tls_reset(drew_kdf_t *ctx);
static int tls_fini(drew_kdf_t *ctx, int flags);
static int tls_setkey(drew_kdf_t *ctx, const uint8_t *key, size_t len);
static int tls_setsalt(drew_kdf_t *ctx, const uint8_t *salt, size_t len);
static int tls_setcount(drew_kdf_t *ctx, size_t count);
static int tls_generate(drew_kdf_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen);
static int tls_test(void *p, DrewLoader *ldr);

static drew_kdf_functbl_t tls_functbl = {
	tls_info, tls_info2, tls_init, tls_clone, tls_reset, tls_fini,
	tls_setkey, tls_setsalt, tls_setcount, tls_generate, tls_test
};

int tls_info(int op, void *p)
{
	drew_kdf_t *kdf = p;
	struct tls *ctx;

	switch (op) {
		case DREW_KDF_VERSION:
			return CURRENT_ABI;
		case DREW_KDF_SIZE:
		case DREW_KDF_BLKSIZE:
			if (!p)
				return -DREW_ERR_MORE_INFO;
			ctx = kdf->ctx;
			return ctx->prf.functbl->info(op, &ctx->prf);
		case DREW_KDF_ENDIAN:
			return 0;
		case DREW_KDF_INTSIZE:
			return sizeof(struct tls);
	}
	return -DREW_ERR_INVALID;
}

int tls_info2(const drew_kdf_t *kdf, int op, drew_param_t *out,
		const drew_param_t *in)
{
	struct tls *ctx;
	switch (op) {
		case DREW_KDF_VERSION:
			return CURRENT_ABI;
		case DREW_KDF_SIZE_CTX:
		case DREW_KDF_BLKSIZE_CTX:
			if (!kdf)
				return -DREW_ERR_MORE_INFO;
			ctx = kdf->ctx;
			return ctx->prf.functbl->info2(&ctx->prf, op, NULL, NULL);
		case DREW_KDF_ENDIAN:
			return 0;
		case DREW_KDF_INTSIZE:
			return sizeof(struct tls);
	}
	return -DREW_ERR_INVALID;
}

int tls_init(drew_kdf_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	drew_kdf_t *prf = NULL;
	drew_hash_t *algo = NULL;
	struct tls *c = ctx->ctx;
	int res = 0;

	for (; param; param = param->next) {
		if (!strcmp(param->name, "digest"))
			algo = param->param.value;
		if (!strcmp(param->name, "prf"))
			prf = param->param.value;
	}

	if (!algo && !prf)
		return -DREW_ERR_MORE_INFO;

	if (!(flags & DREW_KDF_FIXED))
		c = drew_mem_malloc(sizeof(*c));

	if (!c)
		return -ENOMEM;

	if (prf)
		prf->functbl->clone(&c->prf, prf, 0);
	else if (!ldr)
		return -DREW_ERR_MORE_INFO;
	else {
		int id, res = 0;
		const void *functbl;

		id = drew_loader_lookup_by_name(ldr, "HMAC-KDF", 0, -1);
		if (id < 0)
			return id;

		drew_loader_get_functbl(ldr, id, &functbl);
		c->prf.functbl = functbl;
		if ((res = c->prf.functbl->init(&c->prf, 0, ldr, param)) < 0)
			return res;
	}
	c->prf.functbl->reset(&c->prf);
	res = c->prf.functbl->info2(&c->prf, DREW_KDF_SIZE_CTX, NULL, NULL);
	if (res < 0)
		return res;
	c->prfsz = res;
	ctx->ctx = c;
	ctx->functbl = &tls_functbl;

	return 0;
}

int tls_clone(drew_kdf_t *new, const drew_kdf_t *old, int flags)
{
	struct tls *c = new->ctx, *cold = old->ctx;

	if (!(flags & DREW_KDF_FIXED))
		c = drew_mem_malloc(sizeof(*c));

	if (!c)
		return -ENOMEM;

	cold->prf.functbl->clone(&c->prf, &cold->prf, 0);
	c->prfsz = cold->prfsz;
	c->prf.functbl->reset(&c->prf);
	new->functbl = old->functbl;

	return 0;
}

int tls_reset(drew_kdf_t *ctx)
{
	struct tls *c = ctx->ctx;
	return c->prf.functbl->reset(&c->prf);
}

int tls_fini(drew_kdf_t *ctx, int flags)
{
	struct tls *c = ctx->ctx;

	c->prf.functbl->fini(&c->prf, 0);
	if (!(flags & DREW_KDF_FIXED))
		free(c);

	return 0;
}

int tls_setkey(drew_kdf_t *ctx, const uint8_t *key, size_t len)
{
	struct tls *c = ctx->ctx;
	return c->prf.functbl->setkey(&c->prf, key, len);
}

int tls_setsalt(drew_kdf_t *ctx, const uint8_t *salt, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

int tls_setcount(drew_kdf_t *ctx, size_t count)
{
	return -DREW_ERR_NOT_ALLOWED;
}

int tls_generate(drew_kdf_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	struct tls *c = ctx->ctx;
	uint8_t buf[BUFFER_SIZE];
	uint8_t ai[BUFFER_SIZE];
	uint8_t *tmp;
	drew_kdf_t aprf;
	size_t off = 0, tmplen = c->prfsz + inlen;

	c->prf.functbl->clone(&aprf, &c->prf, 0);
	tmp = drew_mem_smalloc(tmplen);
	memcpy(tmp+c->prfsz, in, inlen);

	// Generate A(1).
	aprf.functbl->generate(&aprf, ai, c->prfsz, in, inlen);

	for (size_t i = 0; i < (outlen + c->prfsz - 1) / c->prfsz;
			i++, off += c->prfsz) {
		aprf.functbl->reset(&aprf);
		c->prf.functbl->reset(&c->prf);
		memcpy(tmp, ai, c->prfsz);

		// Generate the next A(i).
		aprf.functbl->generate(&aprf, ai, c->prfsz, ai, c->prfsz);
		c->prf.functbl->generate(&c->prf, buf, c->prfsz, tmp, tmplen);
		memcpy(out+off, buf, MIN(c->prfsz, outlen-off));
	}

	memset(buf, 0, sizeof(buf));
	memset(ai, 0, sizeof(ai));
	drew_mem_sfree(tmp);
	aprf.functbl->fini(&aprf, 0);

	return 0;
}

static int tls_test(void *p, DrewLoader *ldr)
{
#if 0
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

	if ((tres = tls_test_md5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	return result;
#else
	return -DREW_ERR_NOT_IMPL;
#endif
}

struct plugin {
	const char *name;
	const void *functbl;
};

static struct plugin plugin_data[] = {
	{ "TLS-PRF", &tls_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(tls_prf)(void *ldr, int op, int id, void *p)
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
			return DREW_TYPE_KDF;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_kdf_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_kdf_functbl_t));
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
