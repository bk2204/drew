#ifndef BLOCK_PLUGIN_HH
#define BLOCK_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include "block.h"
#include "block-plugin.h"

#define DIM(x) (sizeof(x)/sizeof(x[0]))

#define PLUGIN_STRUCTURE(prefix, bname) \
 \
static int prefix ## info(int op, void *p) \
{ \
	switch (op) { \
		case DREW_BLOCK_VERSION: \
			return 0; \
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
 \
static void prefix ## init(void **ctx, drew_loader_t *, const drew_param_t *) \
{ \
	bname *p = new bname; \
	*ctx = p; \
} \
 \
static int prefix ## clone(void **newctx, void *oldctx, int flags) \
{ \
	bname *p = new bname(*reinterpret_cast<bname *>(oldctx)); \
	if (flags & DREW_BLOCK_CLONE_FIXED) { \
		memcpy(*newctx, p, sizeof(*p)); \
		delete p; \
	} \
	else \
		*newctx = p; \
	return 0; \
} \
 \
static int prefix ## setkey(void *ctx, const uint8_t *key, size_t len) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->SetKey(key, len); \
	return 0; \
} \
 \
static void prefix ## encrypt(void *ctx, uint8_t *out, const uint8_t *in) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->Encrypt(out, in); \
} \
 \
static void prefix ## decrypt(void *ctx, uint8_t *out, const uint8_t *in) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->Decrypt(out, in); \
} \
 \
static void prefix ## fini(void **ctx) \
{ \
	bname *p = reinterpret_cast<bname *>(*ctx); \
	delete p; \
	*ctx = NULL; \
} \
 \
static int prefix ## test(void *); \
 \
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## setkey, prefix ## encrypt, prefix ## decrypt, prefix ## test, prefix ## fini, prefix ## clone);

#endif
