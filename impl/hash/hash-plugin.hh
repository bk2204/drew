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
#ifndef HASH_PLUGIN_HH
#define HASH_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <drew/hash.h>
#include "hash-plugin.h"

#define PLUGIN_STRUCTURE(prefix, hname) \
PLUGIN_STRUCTURE2(prefix, hname) \
static int prefix ## info(int op, void *) \
{ \
	using namespace drew; \
	switch (op) { \
		case DREW_HASH_VERSION: \
			return 2; \
		case DREW_HASH_QUANTUM: \
			return sizeof(hname::quantum_t); \
		case DREW_HASH_SIZE: \
			return hname::digest_size; \
		case DREW_HASH_BLKSIZE: \
			return hname::block_size; \
		case DREW_HASH_BUFSIZE: \
			return hname::buffer_size; \
		case DREW_HASH_INTSIZE: \
			return sizeof(hname); \
		case DREW_HASH_ENDIAN: \
			return hname::endian_t::GetEndianness(); \
		default: \
			return -DREW_ERR_INVALID; \
	} \
} \
 \
static int prefix ## init(drew_hash_t *ctx, int flags, const drew_loader_t *, \
		const drew_param_t *) \
{ \
	using namespace drew; \
	hname *p; \
	if (flags & DREW_HASH_FIXED) \
		p = new (ctx->ctx) hname; \
	else \
		p = new hname; \
	ctx->ctx = p; \
	ctx->functbl = &prefix ## functbl; \
	return 0; \
}

#define PLUGIN_STRUCTURE2(prefix, hname) \
 \
static int prefix ## info(int op, void *); \
static int prefix ## init(drew_hash_t *ctx, int flags, const drew_loader_t *, \
		const drew_param_t *); \
static int prefix ## clone(drew_hash_t *newctx, const drew_hash_t *oldctx, \
		int flags); \
static int prefix ## reset(drew_hash_t *ctx); \
static int prefix ## update(drew_hash_t *ctx, const uint8_t *data, size_t len); \
static int prefix ## updatefast(drew_hash_t *ctx, const uint8_t *data, \
		size_t len); \
static int prefix ## pad(drew_hash_t *ctx); \
static int prefix ## final(drew_hash_t *ctx, uint8_t *digest, int flags); \
static int prefix ## transform(const drew_hash_t *, void *state, \
		const uint8_t *data); \
static int prefix ## fini(drew_hash_t *ctx, int flags); \
static int prefix ## test(void *, const drew_loader_t *); \
 \
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## update, prefix ## updatefast, prefix ## pad, prefix ## final, prefix ## transform, prefix ## test, prefix ## fini, prefix ## clone, prefix ## reset); \
 \
static int prefix ## clone(drew_hash_t *newctx, const drew_hash_t *oldctx, \
		int flags) \
{ \
	using namespace drew; \
	hname *p; \
	const hname *q = reinterpret_cast<const hname *>(oldctx->ctx); \
	if (flags & DREW_HASH_FIXED) \
		p = new (newctx->ctx) hname(*q); \
	else \
		p = new hname(*q); \
	newctx->ctx = p; \
	newctx->functbl = oldctx->functbl; \
	return 0; \
} \
 \
static int prefix ## reset(drew_hash_t *ctx) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	p->Reset(); \
	return 0; \
} \
 \
static int prefix ## update(drew_hash_t *ctx, const uint8_t *data, size_t len) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	p->Update(data, len); \
	return 0; \
} \
 \
static int prefix ## updatefast(drew_hash_t *ctx, const uint8_t *data, \
		size_t len) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	p->UpdateFast(data, len); \
	return 0; \
} \
 \
static int prefix ## pad(drew_hash_t *ctx) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	p->Pad(); \
	return 0; \
} \
 \
static int prefix ## final(drew_hash_t *ctx, uint8_t *digest, int flags) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	p->GetDigest(digest, flags & DREW_HASH_NO_PAD); \
	return 0; \
} \
 \
static int prefix ## transform(const drew_hash_t *, void *state, \
		const uint8_t *data) \
{ \
	using namespace drew; \
	hname::quantum_t *st = reinterpret_cast<hname::quantum_t *>(state); \
	hname::Transform(st, data); \
	return 0; \
} \
 \
static int prefix ## fini(drew_hash_t *ctx, int flags) \
{ \
	using namespace drew; \
	hname *p = reinterpret_cast<hname *>(ctx->ctx); \
	if (flags & DREW_HASH_FIXED) \
		p->~hname(); \
	else { \
		delete p; \
		ctx->ctx = NULL; \
	} \
	return 0; \
}

#endif
