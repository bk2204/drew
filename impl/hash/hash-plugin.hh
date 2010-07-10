#ifndef HASH_PLUGIN_HH
#define HASH_PLUGIN_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#ifndef HASH_NAME
#error "You're not going to get very far without HASH_NAME."
#endif

#include "hash.h"
#include "hash-plugin.h"

extern "C" {

static int info(int op, void *)
{
	switch (op) {
		case DREW_HASH_VERSION:
			return 0;
		case DREW_HASH_QUANTUM:
			return sizeof(HASH_NAME::quantum_t);
		case DREW_HASH_SIZE:
			return HASH_NAME::digest_size;
		case DREW_HASH_BLKSIZE:
			return HASH_NAME::block_size;
		case DREW_HASH_BUFSIZE:
			return HASH_NAME::buffer_size;
		default:
			return -EINVAL;
	}
}

static void init(void **ctx)
{
	HASH_NAME *p = new HASH_NAME;
	*ctx = p;
}

static void update(void *ctx, const uint8_t *data, size_t len)
{
	HASH_NAME *p = reinterpret_cast<HASH_NAME *>(ctx);
	p->Update(data, len);
}

static void pad(void *ctx)
{
	HASH_NAME *p = reinterpret_cast<HASH_NAME *>(ctx);
	p->Pad();
}

static void final(void *ctx, uint8_t *digest)
{
	HASH_NAME *p = reinterpret_cast<HASH_NAME *>(ctx);
	p->GetDigest(digest);
}

static void transform(void *, void *state, const uint8_t *data)
{
	HASH_NAME::quantum_t *st = reinterpret_cast<HASH_NAME::quantum_t *>(state);
	HASH_NAME::Transform(st, data);
}

PLUGIN_FUNCTBL(info, init, update, pad, final, transform);
PLUGIN_INTERFACE()

}

#endif
