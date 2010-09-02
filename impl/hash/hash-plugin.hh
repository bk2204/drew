#ifndef HASH_PLUGIN_HH
#define HASH_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include "hash.h"
#include "hash-plugin.h"

#define PLUGIN_STRUCTURE(prefix, hname, uname) \
 \
static int prefix ## info(int op, void *) \
{ \
	switch (op) { \
		case DREW_HASH_VERSION: \
			return 1; \
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
		default: \
			return -EINVAL; \
	} \
} \
 \
static int prefix ## init(void **ctx, void *q, int flags, drew_loader_t *, \
		const drew_param_t *) \
{ \
	hname *p = new hname; \
	if (flags & DREW_HASH_INIT_FIXED) { \
		memcpy(*ctx, p, sizeof(*p)); \
		delete p; \
	} \
	else \
		*ctx = p; \
	return 0; \
} \
 \
static int prefix ## clone(void **newctx, void *oldctx, int flags) \
{ \
	hname *p = new hname(*reinterpret_cast<hname *>(oldctx)); \
	if (flags & DREW_HASH_CLONE_FIXED) { \
		memcpy(*newctx, p, sizeof(*p)); \
		delete p; \
	} \
	else \
		*newctx = p; \
	return 0; \
} \
 \
static int prefix ## update(void *ctx, const uint8_t *data, size_t len) \
{ \
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->Update(data, len); \
	return 0; \
} \
 \
static int prefix ## pad(void *ctx) \
{ \
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->Pad(); \
	return 0; \
} \
 \
static int prefix ## final(void *ctx, uint8_t *digest, int flags) \
{ \
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->GetDigest(digest, flags & DREW_HASH_FINAL_NO_PAD); \
	return 0; \
} \
 \
static int prefix ## transform(void *, void *state, const uint8_t *data) \
{ \
	hname::quantum_t *st = reinterpret_cast<hname::quantum_t *>(state); \
	hname::Transform(st, data); \
	return 0; \
} \
 \
static int prefix ## fini(void **ctx, int flags) \
{ \
	hname *p = reinterpret_cast<hname *>(*ctx); \
	if (flags & DREW_HASH_FINI_NO_DEALLOC) \
		p->~uname(); \
	else { \
		delete p; \
		*ctx = NULL; \
	} \
	return 0; \
} \
 \
static int prefix ## test(void *, drew_loader_t *); \
 \
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## update, prefix ## pad, prefix ## final, prefix ## transform, prefix ## test, prefix ## fini, prefix ## clone);

#endif
