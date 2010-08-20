#ifndef HASH_PLUGIN_HH
#define HASH_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include "hash.h"
#include "hash-plugin.h"

#define PLUGIN_STRUCTURE(prefix, hname) \
 \
static int prefix ## info(int op, void *) \
{ \
	switch (op) { \
		case DREW_HASH_VERSION: \
			return 0; \
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
static void prefix ## init(void **ctx, drew_loader_t *, const drew_param_t *) \
{ \
	hname *p = new hname; \
	*ctx = p; \
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
static void prefix ## update(void *ctx, const uint8_t *data, size_t len) \
{ \
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->Update(data, len); \
} \
 \
static void prefix ## pad(void *ctx) \
{ \
	/* Do nothing, because final will pad automatically. */ \
} \
 \
static void prefix ## final(void *ctx, uint8_t *digest) \
{ \
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->GetDigest(digest); \
} \
 \
static void prefix ## transform(void *, void *state, const uint8_t *data) \
{ \
	hname::quantum_t *st = reinterpret_cast<hname::quantum_t *>(state); \
	hname::Transform(st, data); \
} \
 \
static void prefix ## fini(void **ctx) \
{ \
	hname *p = reinterpret_cast<hname *>(*ctx); \
	delete p; \
	*ctx = NULL; \
} \
 \
static int prefix ## test(void *); \
 \
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## update, prefix ## pad, prefix ## final, prefix ## transform, prefix ## test, prefix ## fini, prefix ## clone);

#endif
