#ifndef BLOCK_PLUGIN_HH
#define BLOCK_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include "block.h"
#include "block-plugin.h"

#define DIM(x) (sizeof(x)/sizeof(x[0]))

#define PLUGIN_STRUCTURE(prefix, bname, uname) \
 \
static int prefix ## info(int op, void *p) \
{ \
	switch (op) { \
		case DREW_BLOCK_VERSION: \
			return 1; \
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
static int prefix ## init(void **ctx, void *data, int flags, drew_loader_t *, const drew_param_t *) \
{ \
	bname *p = new bname; \
	if (flags & DREW_BLOCK_INIT_FIXED) { \
		memcpy(*ctx, p, sizeof(*p)); \
		delete p;\
	} \
	else \
		*ctx = p; \
	return 0; \
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
static int prefix ## setkey(void *ctx, const uint8_t *key, size_t len, int mode) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->SetKey(key, len); \
	return 0; \
} \
 \
static int prefix ## encrypt(void *ctx, uint8_t *out, const uint8_t *in) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->Encrypt(out, in); \
	return 0; \
} \
 \
static int prefix ## decrypt(void *ctx, uint8_t *out, const uint8_t *in) \
{ \
	bname *p = reinterpret_cast<bname *>(ctx); \
	p->Decrypt(out, in); \
	return 0; \
} \
 \
static int prefix ## fini(void **ctx, int flags) \
{ \
	bname *p = reinterpret_cast<bname *>(*ctx); \
	if (flags & DREW_BLOCK_FINI_NO_DEALLOC) \
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
PLUGIN_FUNCTBL(prefix, prefix ## info, prefix ## init, prefix ## setkey, prefix ## encrypt, prefix ## decrypt, prefix ## test, prefix ## fini, prefix ## clone);

#endif
