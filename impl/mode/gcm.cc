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

#define TABLE_SIZE (64 * 1024)
#include "gcm-impl.cc"

HIDE()

typedef BigEndian E;

extern "C" {

struct gcm;

static int gcm_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int gcmfl_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);

/* The slow implementation. */
static const drew_mode_functbl_t gcm_functbl = {
	gcm_info, gcm_info2, gcm_init, gcm_clone, gcm_reset, gcm_fini,
	gcm_setblock, gcm_setiv, gcm_encrypt, gcm_decrypt,
	gcm_encryptfast, gcm_decryptfast, gcm_setdata,
	gcm_encryptfinal, gcm_decryptfinal, gcm_resync, gcm_test
};
/* The fastest implementation which uses large tables. */
static const drew_mode_functbl_t gcmfl_functbl = {
	gcm_info, gcm_info2, gcmfl_init, gcm_clone, gcm_reset, gcm_fini,
	gcm_setblock, gcm_setiv, gcm_encrypt, gcm_decrypt,
	gcm_encryptfast, gcm_decryptfast, gcm_setdata,
	gcm_encryptfinal, gcm_decryptfinal, gcm_resync, gcm_test
};

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
