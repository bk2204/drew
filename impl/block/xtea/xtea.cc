#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.h"
#include "xtea.hh"
#include "btestcase.hh"

extern "C" {

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static const int xteakeysz[] =
{
	16
};

static int xteatest(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<XTEA>("27f917b1c1da899360e2acaaa6eb923d", 16).Test("af20a390547571aa",
			"d26428af0a202283");

	return res;
}

	PLUGIN_STRUCTURE2(xtea, XTEA)
	PLUGIN_DATA_START()
	PLUGIN_DATA(xtea, "XTEA")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(xtea)

static int xteainfo(int op, void *p)
{
	using namespace drew;
	switch (op) {
		case DREW_BLOCK_VERSION:
			return 2;
		case DREW_BLOCK_BLKSIZE:
			return XTEA::block_size;
		case DREW_BLOCK_KEYSIZE:
			for (size_t i = 0; i < DIM(xteakeysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (xteakeysz[i] > *x)
					return xteakeysz[i];
			}
			return 0;
		case DREW_BLOCK_INTSIZE:
			return sizeof(XTEA);
		default:
			return -EINVAL;
	}
}

static int xteainit(drew_block_t *ctx, int flags,
		const drew_loader_t *, const drew_param_t *param)
{
	using namespace drew;
	XTEA *p;
	size_t rounds = 32;

	for (const drew_param_t *q = param; q; q = q->next)
		if (!strcmp("rounds", q->name))
			rounds = q->param.number;

	if (flags & DREW_BLOCK_FIXED)
		p = new (ctx->ctx) XTEA(rounds);
	else
		p = new XTEA(rounds);
	ctx->ctx = p;
	ctx->functbl = &xteafunctbl;
	return 0;
}
}

typedef drew::XTEA::endian_t E;

int drew::XTEA::SetKey(const uint8_t *key, size_t len)
{
	E::Copy(m_k, key, len);
	return 0;
}

int drew::XTEA::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t v[2];

	E::Copy(v, in, sizeof(v));

	const uint32_t delta = 0x9e3779b9;
	uint32_t y = v[0], z = v[1];
	uint32_t sum = 0;

	for (size_t i = 0; i < rounds; i++) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + m_k[sum & 3]);
		sum += delta;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + m_k[(sum >> 11) & 3]);
	}

	v[0] = y;
	v[1] = z;

	E::Copy(out, v, sizeof(v));
	return 0;
}

int drew::XTEA::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t v[2];

	E::Copy(v, in, sizeof(v));

	const uint32_t delta = 0x9e3779b9;
	uint32_t y = v[0], z = v[1];
	uint32_t sum = delta * rounds;

	for (size_t i = rounds; i > 0; i--) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + m_k[(sum >> 11) & 3]);
		sum -= delta;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + m_k[sum & 3]);
	}

	v[0] = y;
	v[1] = z;

	E::Copy(out, v, sizeof(v));
	return 0;
}
