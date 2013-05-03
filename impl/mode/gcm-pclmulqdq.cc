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
/*-
 * The implementation of GCM is from OpenBSD
 * (src/sys/arch/amd64/amd64/aes_intel.S) and has the following copyright and
 * license:
 *
 * Copyright (C) 2008-2010, Intel Corporation
 *    Author: Huang Ying <ying.huang@intel.com>
 *            Vinodh Gopal <vinodh.gopal@intel.com>
 *            Kahraman Akdemir
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products
 *   derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#if defined(DREW_COMPILER_GCCLIKE) && defined(VECTOR_T)
#if (defined(__i386__) || defined(__amd64__)) && defined(__PCLMUL__)
#define FEATURE_PCLMULQDQ

typedef long long int vector_t __attribute__((vector_size(16)));
typedef int vector4i_t __attribute__((vector_size(16)));
#endif
#endif

#ifdef FEATURE_PCLMULQDQ
#include "gcm-impl.cc"
#else
struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};
#endif

HIDE()

typedef BigEndian E;

extern "C" {

#ifdef FEATURE_PCLMULQDQ
struct gcm;

static int gcm_init(drew_mode_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param);

/* The PCLMULQDQ implementation. */
static const drew_mode_functbl_t gcm_functbl = {
	gcm_info, gcm_info2, gcm_init, gcm_clone, gcm_reset, gcm_fini,
	gcm_setblock, gcm_setiv, gcm_encrypt, gcm_decrypt,
	gcm_encryptfast, gcm_decryptfast, gcm_setdata,
	gcm_encryptfinal, gcm_decryptfinal, gcm_resync, gcm_test
};

static inline void mul(struct gcm *ctx, uint8_t *buf);

static int gcm_init(drew_mode_t *ctx, int flags, DrewLoader *ldr,
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

static inline void mul(struct gcm *ctx, uint8_t *buf)
{
	vector_t a, b, res;
	vector_t t3, t4, t5, t6;
	E::Copy(&a, buf, sizeof(a));
	b = ctx->hv;

	t3 = __builtin_ia32_pclmulqdq128(a, b, 0x00);
	t4 = __builtin_ia32_pclmulqdq128(a, b, 0x01);
	t5 = __builtin_ia32_pclmulqdq128(a, b, 0x10);
	t6 = __builtin_ia32_pclmulqdq128(a, b, 0x11);

	t4 ^= t5;
	t5 = t4;
	t4 = __builtin_ia32_psrldqi128(t4, 8*8);
	t5 = __builtin_ia32_pslldqi128(t5, 8*8);
	t3 ^= t5;
	t6 ^= t4;
	vector_t t7 = t3, t8 = t6;
	t3 = vector_t(__builtin_ia32_pslldi128(vector4i_t(t3), 1));
	t6 = vector_t(__builtin_ia32_pslldi128(vector4i_t(t6), 1));
	t7 = vector_t(__builtin_ia32_psrldi128(vector4i_t(t7), 31));
	t8 = vector_t(__builtin_ia32_psrldi128(vector4i_t(t8), 31));
	vector_t t9 = t7;
	t8 = __builtin_ia32_pslldqi128(t8, 8*4);
	t7 = __builtin_ia32_pslldqi128(t7, 8*4);
	t9 = __builtin_ia32_psrldqi128(t9, 8*12);
	t3 |= t7;
	t6 |= t8;
	t6 |= t9;

	t7 = t3;
	t8 = t3;
	t9 = t3;
	t7 = vector_t(__builtin_ia32_pslldi128(vector4i_t(t7), 31));
	t8 = vector_t(__builtin_ia32_pslldi128(vector4i_t(t8), 30));
	t9 = vector_t(__builtin_ia32_pslldi128(vector4i_t(t9), 25));
	t7 ^= t8;
	t7 ^= t9;
	t8 = t7;
	t7 = __builtin_ia32_pslldqi128(t7, 8*12);
	t8 = __builtin_ia32_psrldqi128(t8, 8*4);
	t3 ^= t7;

	vector_t t2;
	t2 = t3;
	t4 = t3;
	t5 = t3;
	t2 = vector_t(__builtin_ia32_psrldi128(vector4i_t(t2), 1));
	t4 = vector_t(__builtin_ia32_psrldi128(vector4i_t(t4), 2));
	t5 = vector_t(__builtin_ia32_psrldi128(vector4i_t(t5), 7));
	t2 ^= t4;
	t2 ^= t5;
	t2 ^= t8;
	t3 ^= t2;
	t6 ^= t3;
	res = t6;

	E::Copy(buf, &res, sizeof(res));
}
#endif

inline bool HasPCLMULQDQ()
{
#if defined(__i386__) || defined(__amd64__)
	int res = 0;
	uint32_t a, b, c, d;
	res = GetCpuid(1, a, b, c, d);
	if (res)
		return false;
	return c & 0x00000002;
#else
	return false;
#endif
}

static struct plugin plugin_data[] = {
#ifdef FEATURE_PCLMULQDQ
	{ "GCM", &gcm_functbl }
#endif
};

EXPORT()
int DREW_PLUGIN_NAME(gcm_pclmulqdq)(void *ldr, int op, int id, void *p)
{
	int nplugins = HasPCLMULQDQ() ?
		sizeof(plugin_data)/sizeof(plugin_data[0]) : 0;

	if (id < 0 || id >= nplugins) {
		if (!id && !nplugins && op == DREW_LOADER_GET_NPLUGINS)
			return 0;
		else
			return -DREW_ERR_INVALID;
	}

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
