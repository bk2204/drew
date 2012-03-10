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
#include "prng.hh"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#include "prng-plugin.h"

#include <algorithm>
#include <utility>

HIDE()
template<class T>
inline static int prng_info(int op, void *p, int blksize)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE:
		case DREW_PRNG_BLKSIZE_CTX:
			return blksize;
		case DREW_PRNG_SEEDABLE:
			return 0;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(T);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

template<class T>
static int prng_fini(drew_prng_t *ctx, int flags)
{
	T *p = reinterpret_cast<T *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~T();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

template<class T>
static int prng_init(drew_prng_t *ctx, int flags,
		const drew_prng_functbl_t *tbl)
{
	int res = 0;
	T *p;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) T;
	else
		p = new T;

	ctx->ctx = p;
	res = p->CheckImplementation();
	if (res < 0) {
		prng_fini<T>(ctx, flags);
		return res;
	}
	ctx->functbl = tbl;
	return 0;
}

template<class T>
static int prng_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	T *p;
	const T *q = reinterpret_cast<const T *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) T(*q);
	else
		p = new T(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}
extern "C" {

static int prng_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int prng_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int prng_entropy(const drew_prng_t *ctx);
static int prng_test(void *, const drew_loader_t *);

static int dur_info(int op, void *p);
static int dur_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int dur_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int dur_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int dur_fini(drew_prng_t *ctx, int flags);

#ifdef __RDRND__
static int rdrand_info(int op, void *p);
static int rdrand_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int rdrand_clone(drew_prng_t *newctx, const drew_prng_t *oldctx,
		int flags);
static int rdrand_fini(drew_prng_t *ctx, int flags);
PLUGIN_FUNCTBL(rdrand, rdrand_info, rdrand_info2, rdrand_init, rdrand_clone, rdrand_fini, prng_seed, prng_bytes, prng_entropy, prng_test);
#endif

PLUGIN_FUNCTBL(dur, dur_info, dur_info2, dur_init, dur_clone, dur_fini, prng_seed, prng_bytes, prng_entropy, prng_test);


static int prng_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::SystemPRNG *p = reinterpret_cast<drew::SystemPRNG *>(ctx->ctx);
	return p->AddRandomData(key, len, entropy);
}

static int prng_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::SystemPRNG *p = reinterpret_cast<drew::SystemPRNG *>(ctx->ctx);
	return p->GetBytes(out, len);
}

static int prng_entropy(const drew_prng_t *ctx)
{
	const drew::SystemPRNG *p =
		reinterpret_cast<const drew::SystemPRNG *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

static int prng_test(void *, const drew_loader_t *)
{
	return -DREW_ERR_NOT_IMPL;
}

static int dur_info(int op, void *p)
{
	return prng_info<drew::DevURandom>(op, p, 1);
}

static int dur_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *)
{
	return prng_info<drew::DevURandom>(op, NULL, 1);
}

static int dur_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	return prng_init<drew::DevURandom>(ctx, flags, &durfunctbl);
}

static int dur_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	return prng_clone<drew::DevURandom>(newctx, oldctx, flags);
}

static int dur_fini(drew_prng_t *ctx, int flags)
{
	return prng_fini<drew::DevURandom>(ctx, flags);
}

#ifdef __RDRND__
static int rdrand_info(int op, void *p)
{
	return prng_info<drew::RDRAND>(op, p, 4);
}

static int rdrand_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *)
{
	return prng_info<drew::RDRAND>(op, NULL, 4);
}

static int rdrand_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	return prng_init<drew::RDRAND>(ctx, flags, &rdrandfunctbl);
}

static int rdrand_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	return prng_clone<drew::RDRAND>(newctx, oldctx, flags);
}

static int rdrand_fini(drew_prng_t *ctx, int flags)
{
	return prng_fini<drew::RDRAND>(ctx, flags);
}
#endif

	PLUGIN_DATA_START()
	PLUGIN_DATA(dur, "DevURandom")
#ifdef __RDRND__
	PLUGIN_DATA(rdrand, "RDRAND")
#endif
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(sysprng)
}

UNHIDE()
