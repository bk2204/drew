#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.h"
#include "rc2.hh"
#include "btestcase.hh"

extern "C" {

	PLUGIN_STRUCTURE2(rc2, RC2)
	PLUGIN_DATA_START()
	PLUGIN_DATA(rc2, "RC2")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(rc2)

static int rc2info(int op, void *p)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return 2;
		case DREW_BLOCK_BLKSIZE:
			return 8;
		case DREW_BLOCK_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				if (*x < 1024/8)
					return *x + 1;
			}
			return 0;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::RC2);
		default:
			return -EINVAL;
	}
}

static int rc2init(drew_block_t *ctx, int flags,
		const drew_loader_t *, const drew_param_t *)
{
	using namespace drew;
	RC2 *p;

	if (flags & DREW_BLOCK_FIXED)
		p = new (ctx->ctx) RC2;
	else
		p = new RC2;
	ctx->ctx = p;
	ctx->functbl = &rc2functbl;
	return 0;
}

static int rc2test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<RC2>("ffffffffffffffff", 8).Test("ffffffffffffffff",
			"278b27e42e2f0d49");
	res <<= 2;
	res |= BlockTestCase<RC2>("3000000000000000", 8).Test("1000000000000001",
			"30649edf9be7d2c2");
	res <<= 2;
	res |= BlockTestCase<RC2>("88bca90e90875a7f0f79c384627bafb2", 16).Test("0000000000000000",
			"2269552ab0f85ca6");


	return res;
}
}

typedef drew::RC2::endian_t E;

drew::RC2::RC2()
{
}

int drew::RC2::SetKey(const uint8_t *key, size_t len)
{
	uint8_t k[128];
	const size_t t8 = len;
	const uint8_t tm = 0xff;

	memcpy(k, key, len);

	for (size_t i = len; i < 128; i++)
		k[i] = pitable[uint8_t(k[i-1] + k[i-len])];

	k[128-t8] = pitable[k[128-t8] & tm];

	for (ssize_t i = 127-t8; i >= 0; i--)
		k[i] = pitable[k[i+1] ^ k[i+t8]];

	E::Copy(m_k, k, sizeof(k));
	return 0;
}

#define R(i, x) (r[((i)+(x)) & 3])
void drew::RC2::Mix(uint16_t *r, size_t i, size_t j, size_t s) const
{
	r[i] += m_k[j] + (R(i, 3) & R(i, 2)) + ((~R(i, 3)) & R(i, 1));
	r[i] = RotateLeft(r[i], s);
}

void drew::RC2::MixRound(uint16_t *r, size_t j) const
{
	Mix(r, 0, j+0, 1);
	Mix(r, 1, j+1, 2);
	Mix(r, 2, j+2, 3);
	Mix(r, 3, j+3, 5);
}

void drew::RC2::Mash(uint16_t *r, size_t i) const
{
	r[i] += m_k[R(i, 3) & 63];
}

void drew::RC2::MashRound(uint16_t *r) const
{
	Mash(r, 0);
	Mash(r, 1);
	Mash(r, 2);
	Mash(r, 3);
}

int drew::RC2::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint16_t r[4];
	size_t j = 0;

	E::Copy(r, in, sizeof(r));

	for (size_t i = 0; i < 5; i++, j+=4)
		MixRound(r, j);
	MashRound(r);
	for (size_t i = 0; i < 6; i++, j+=4)
		MixRound(r, j);
	MashRound(r);
	for (size_t i = 0; i < 5; i++, j+=4)
		MixRound(r, j);

	E::Copy(out, r, sizeof(r));
	return 0;
}

void drew::RC2::RMix(uint16_t *r, size_t i, size_t j, size_t s) const
{
	r[i] = RotateRight(r[i], s);
	r[i] -= m_k[j] + (R(i, 3) & R(i, 2)) + ((~R(i, 3)) & R(i, 1));
}

void drew::RC2::RMixRound(uint16_t *r, size_t j) const
{
	RMix(r, 3, j+3, 5);
	RMix(r, 2, j+2, 3);
	RMix(r, 1, j+1, 2);
	RMix(r, 0, j+0, 1);
}

void drew::RC2::RMash(uint16_t *r, size_t i) const
{
	r[i] -= m_k[R(i, 3) & 63];
}

void drew::RC2::RMashRound(uint16_t *r) const
{
	RMash(r, 3);
	RMash(r, 2);
	RMash(r, 1);
	RMash(r, 0);
}

int drew::RC2::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint16_t r[4];
	size_t j = 60;

	E::Copy(r, in, sizeof(r));

	for (size_t i = 0; i < 5; i++, j-=4)
		RMixRound(r, j);
	RMashRound(r);
	for (size_t i = 0; i < 6; i++, j-=4)
		RMixRound(r, j);
	RMashRound(r);
	for (size_t i = 0; i < 5; i++, j-=4)
		RMixRound(r, j);

	E::Copy(out, r, sizeof(r));
	return 0;
}

const uint8_t drew::RC2::pitable[] = {
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
	0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
	0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
	0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
	0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
	0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
	0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
	0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
	0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
	0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
	0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
	0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
	0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
	0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
	0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
	0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
	0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};
