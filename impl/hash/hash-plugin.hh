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
		default: \
			return -EINVAL; \
	} \
} \
 \
static void prefix ## init(void **ctx) \
{ \
	hname *p = new hname; \
	*ctx = p; \
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
	hname *p = reinterpret_cast<hname *>(ctx); \
	p->Pad(); \
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
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## update, prefix ## pad, prefix ## final, prefix ## transform);

#endif
