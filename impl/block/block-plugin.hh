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
#ifndef BLOCK_PLUGIN_HH
#define BLOCK_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <new>

#include <drew/block.h>
#ifndef BLOCK_NO_MACROS
#include "block-plugin.h"
#endif
#include "util.hh"

HIDE()
namespace drew {
	template<size_t BlockSize>
	class BlockCipher {
		public:
			static const size_t block_size = BlockSize;
			typedef AlignedBlock<uint8_t, BlockSize> FastBlock;
			virtual ~BlockCipher() {}
			virtual int Reset()
			{
				return 0;
			}
			virtual int SetKey(const uint8_t *key, size_t len) = 0;
			virtual int Encrypt(uint8_t *out, const uint8_t *in) const = 0;
			virtual int Decrypt(uint8_t *out, const uint8_t *in) const = 0;
			virtual int EncryptFast(FastBlock *bout, const FastBlock *bin,
					size_t n) const
			{
				// This takes minimal, if any, advantage of the alignment.
				if (BlockSize == 8) {
					for (size_t i = 0; i < n; i++, bout++, bin++) {
						Encrypt(bout->data, bin->data);
						Encrypt(bout->data+8, bin->data+8);
					}
				}
				else if (BlockSize == 16)
					for (size_t i = 0; i < n; i++, bout++, bin++)
						Encrypt(bout->data, bin->data);
				else {
					size_t off = 0;
					for (size_t i = 0; i < n; i++, off += BlockSize)
						Encrypt(bout->data+off, bin->data+off);
				}
				return 0;
			}
			virtual int DecryptFast(FastBlock *bout, const FastBlock *bin,
					size_t n) const
			{
				if (BlockSize == 8) {
					for (size_t i = 0; i < n; i++, bout++, bin++) {
						Decrypt(bout->data, bin->data);
						Decrypt(bout->data+8, bin->data+8);
					}
				}
				else if (BlockSize == 16)
					for (size_t i = 0; i < n; i++, bout++, bin++)
						Decrypt(bout->data, bin->data);
				else {
					size_t off = 0;
					for (size_t i = 0; i < n; i++, off += BlockSize)
						Decrypt(bout->data+off, bin->data+off);
				}
				return 0;
			}
		protected:
		private:
	};
}
UNHIDE()

#define PLUGIN_STRUCTURE(prefix, bname) \
PLUGIN_STRUCTURE2(prefix, bname) \
static int prefix ## info(int op, void *p) \
{ \
	using namespace drew; \
	switch (op) { \
		case DREW_BLOCK_VERSION: \
			return 2; \
		case DREW_BLOCK_BLKSIZE: \
			return bname::block_size; \
		case DREW_BLOCK_KEYSIZE: \
			for (size_t i = 0; i < DIM(prefix ## keysz); i++) { \
				const int *x = reinterpret_cast<int *>(p); \
				if (prefix ## keysz[i] > *x) \
					return prefix ## keysz[i]; \
			} \
			return 0; \
		case DREW_BLOCK_INTSIZE: \
			return sizeof(bname); \
		default: \
			return -EINVAL; \
	} \
} \
static int prefix ## init(drew_block_t *ctx, int flags, \
		const drew_loader_t *, const drew_param_t *) \
{ \
	using namespace drew; \
	bname *p; \
	if (flags & DREW_BLOCK_FIXED) \
		p = new (ctx->ctx) bname; \
	else \
		p = new bname; \
	ctx->ctx = p; \
	ctx->functbl = &prefix ## functbl; \
	return 0; \
}

#define PLUGIN_STRUCTURE2(prefix, bname) \
 \
static int prefix ## info(int op, void *p); \
static int prefix ## init(drew_block_t *ctx, int flags, \
		const drew_loader_t *, const drew_param_t *); \
static int prefix ## clone(drew_block_t *newctx, const drew_block_t *oldctx, \
		int flags); \
static int prefix ## reset(drew_block_t *ctx); \
static int prefix ## setkey(drew_block_t *ctx, const uint8_t *key, size_t len, \
		int mode); \
static int prefix ## encrypt(const drew_block_t *ctx, uint8_t *out, \
		const uint8_t *in); \
static int prefix ## decrypt(const drew_block_t *ctx, uint8_t *out, \
		const uint8_t *in); \
static int prefix ## encryptfast(const drew_block_t *ctx, uint8_t *out, const uint8_t *in, size_t n); \
static int prefix ## decryptfast(const drew_block_t *ctx, uint8_t *out, const uint8_t *in, size_t n); \
static int prefix ## fini(drew_block_t *ctx, int flags); \
static int prefix ## test(void *, const drew_loader_t *); \
 \
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## setkey, prefix ## encrypt, prefix ## decrypt, prefix ## encryptfast, prefix ## decryptfast, prefix ## test, prefix ## fini, prefix ## clone, prefix ## reset); \
 \
static int prefix ## clone(drew_block_t *newctx, const drew_block_t *oldctx, \
		int flags) \
{ \
	using namespace drew; \
	bname *p; \
	const bname *q = reinterpret_cast<const bname *>(oldctx->ctx); \
	if (flags & DREW_BLOCK_FIXED) \
		p = new (newctx->ctx) bname(*q); \
	else \
		p = new bname (*q); \
	newctx->ctx = p; \
	newctx->functbl = oldctx->functbl; \
	return 0; \
} \
 \
static int prefix ## setkey(drew_block_t *ctx, const uint8_t *key, size_t len, \
		int mode) \
{ \
	using namespace drew; \
	bname *p = reinterpret_cast<bname *>(ctx->ctx); \
	return p->SetKey(key, len); \
} \
 \
static int prefix ## reset(drew_block_t *ctx) \
{ \
	using namespace drew; \
	bname *p = reinterpret_cast<bname *>(ctx->ctx); \
	return p->Reset(); \
} \
 \
static int prefix ## encrypt(const drew_block_t *ctx, uint8_t *out, const uint8_t *in) \
{ \
	using namespace drew; \
	const bname *p = reinterpret_cast<const bname *>(ctx->ctx); \
	return p->Encrypt(out, in); \
} \
 \
static int prefix ## decrypt(const drew_block_t *ctx, uint8_t *out, const uint8_t *in) \
{ \
	using namespace drew; \
	const bname *p = reinterpret_cast<const bname *>(ctx->ctx); \
	return p->Decrypt(out, in); \
} \
 \
static int prefix ## encryptfast(const drew_block_t *ctx, uint8_t *out, const uint8_t *in, size_t n) \
{ \
	using namespace drew; \
	typedef bname::FastBlock FastBlock; \
	const bname *p = reinterpret_cast<const bname *>(ctx->ctx); \
	return p->EncryptFast((FastBlock *)out, (const FastBlock *)in, n); \
} \
 \
static int prefix ## decryptfast(const drew_block_t *ctx, uint8_t *out, const uint8_t *in, size_t n) \
{ \
	using namespace drew; \
	typedef bname::FastBlock FastBlock; \
	const bname *p = reinterpret_cast<const bname *>(ctx->ctx); \
	return p->DecryptFast((FastBlock *)out, (const FastBlock *)in, n); \
} \
 \
static int prefix ## fini(drew_block_t *ctx, int flags) \
{ \
	using namespace drew; \
	bname *p = reinterpret_cast<bname *>(ctx->ctx); \
	if (flags & DREW_BLOCK_FIXED) \
		p->~bname(); \
	else { \
		delete p; \
		ctx->ctx = NULL; \
	} \
	return 0; \
}

#endif
