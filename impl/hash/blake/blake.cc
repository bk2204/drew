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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "blake.hh"
#include "testcase.hh"
#include "util.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(blake512, BLAKE512)
PLUGIN_STRUCTURE(blake384, BLAKE384)
PLUGIN_STRUCTURE(blake256, BLAKE256)
PLUGIN_STRUCTURE(blake224, BLAKE224)
PLUGIN_DATA_START()
PLUGIN_DATA(blake512, "BLAKE-512")
PLUGIN_DATA(blake384, "BLAKE-384")
PLUGIN_DATA(blake256, "BLAKE-256")
PLUGIN_DATA(blake224, "BLAKE-224")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(blake)

HIDE()
static int blake256test(void *, const drew_loader_t *)
{
	const uint8_t zero[] = {0x00};
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<BLAKE256>("", 0).Test("716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a");
	res <<= 1;
	res |= !HashTestCase<BLAKE256>("\xcc", 1).Test("e104256a2bc501f459d03fac96b9014f593e22d30f4de525fa680c3aa189eb4f");
	res <<= 1;
	res |= !HashTestCase<BLAKE256>(zero, 1, 1).Test("0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87");

	return res;
}

static int blake224test(void *, const drew_loader_t *)
{
	const uint8_t zero[] = {0x00};
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<BLAKE224>("", 0).Test("7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed");
	res <<= 1;
	res |= !HashTestCase<BLAKE224>("\xcc", 1).Test("5e21c1e375c7bc822046fad96910c95031bd4262ada71b4c91052fea");
	res <<= 1;
	res |= !HashTestCase<BLAKE224>(zero, 1, 1).Test("4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5");

	return res;
}

static int blake512test(void *, const drew_loader_t *)
{
	const uint8_t zero[] = {0x00};
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<BLAKE512>("", 0).Test("a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8");
	res <<= 1;
	res |= !HashTestCase<BLAKE512>("\xcc", 1).Test("4f0ef594f20172d23504873f596984c64c1583c7b2abb8d8786aa2aeeae1c46c744b61893d661b0733b76d1fe19257dd68e0ef05422ca25d058dfe6c33d68709");
	res <<= 1;
	res |= !HashTestCase<BLAKE512>(zero, 1, 1).Test("97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3");

	return res;
}

static int blake384test(void *, const drew_loader_t *)
{
	const uint8_t zero[] = {0x00};
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<BLAKE384>("", 0).Test("c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706");
	res <<= 1;
	res |= !HashTestCase<BLAKE384>("\xcc", 1).Test("a77e65c0c03ecb831dbcdd50a3c2bce300d55eac002a9c197095518d8514c0b578e3ecb7415291f99ede91d49197dd05");
	res <<= 1;
	res |= !HashTestCase<BLAKE384>(zero, 1, 1).Test("10281f67e135e90ae8e882251a355510a719367ad70227b137343e1bc122015c29391e8545b5272d13a7c2879da3d807");

	return res;
}
UNHIDE()
}

HIDE()
static const uint32_t k256[] = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
};

static const int sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13 ,0},
};

typedef BigEndian E;

drew::BLAKE256::BLAKE256()
{
	Reset();
}

void drew::BLAKE256::Reset()
{
	m_hash[ 0] = 0x6a09e667;
	m_hash[ 1] = 0xbb67ae85;
	m_hash[ 2] = 0x3c6ef372;
	m_hash[ 3] = 0xa54ff53a;
	m_hash[ 4] = 0x510e527f;
	m_hash[ 5] = 0x9b05688c;
	m_hash[ 6] = 0x1f83d9ab;
	m_hash[ 7] = 0x5be0cd19;
	Initialize();
}

drew::BLAKE224::BLAKE224()
{
	Reset();
}

void drew::BLAKE224::Reset()
{
	m_hash[0] = 0xc1059ed8;
	m_hash[1] = 0x367cd507;
	m_hash[2] = 0x3070dd17;
	m_hash[3] = 0xf70e5939;
	m_hash[4] = 0xffc00b31;
	m_hash[5] = 0x68581511;
	m_hash[6] = 0x64f98fa7;
	m_hash[7] = 0xbefa4fa4;
	Initialize();
}

inline void drew::BLAKE256Transform::G(uint32_t &a, uint32_t &b, uint32_t &c,
		uint32_t &d, int r, int i, const uint32_t *m)
{
	a += b + (m[sigma[r][i]] ^ k256[sigma[r][i+1]]);
	d = RotateRight(d ^ a, 16);
	c += d;
	b = RotateRight(b ^ c, 12);
	a += b + (m[sigma[r][i+1]] ^ k256[sigma[r][i]]);
	d = RotateRight(d ^ a, 8);
	c += d;
	b = RotateRight(b ^ c, 7);
}

inline void drew::BLAKE256Transform::Round(uint32_t *v, int r,
		const uint32_t *m)
{
	G(v[ 0], v[ 4], v[ 8], v[12], r,  0, m);
	G(v[ 1], v[ 5], v[ 9], v[13], r,  2, m);
	G(v[ 2], v[ 6], v[10], v[14], r,  4, m);
	G(v[ 3], v[ 7], v[11], v[15], r,  6, m);

	G(v[ 0], v[ 5], v[10], v[15], r,  8, m);
	G(v[ 1], v[ 6], v[11], v[12], r, 10, m);
	G(v[ 2], v[ 7], v[ 8], v[13], r, 12, m);
	G(v[ 3], v[ 4], v[ 9], v[14], r, 14, m);
}

void drew::BLAKE256Transform::Transform(uint32_t *state, const uint8_t *block,
		const uint32_t *lenctr)
{
	uint32_t v[16] ALIGNED_T;
	uint32_t m[16];
	uint32_t len[2];

	E::Copy(m, block, sizeof(m));

	len[1] = (lenctr[1]<<3)|(lenctr[0]>>((sizeof(lenctr[0])*8)-3));
	len[0] = lenctr[0]<<3;

	memcpy(v, state, sizeof(*v)*8);
	v[ 8] = 0x243f6a88;
	v[ 9] = 0x85a308d3;
	v[10] = 0x13198a2e;
	v[11] = 0x03707344;
	v[12] = 0xa4093822 ^ len[0];
	v[13] = 0x299f31d0 ^ len[0];
	v[14] = 0x082efa98 ^ len[1];
	v[15] = 0xec4e6c89 ^ len[1];

	Round(v, 0, m);
	Round(v, 1, m);
	Round(v, 2, m);
	Round(v, 3, m);
	Round(v, 4, m);
	Round(v, 5, m);
	Round(v, 6, m);
	Round(v, 7, m);
	Round(v, 8, m);
	Round(v, 9, m);
	Round(v, 0, m);
	Round(v, 1, m);
	Round(v, 2, m);
	Round(v, 3, m);

	XorAligned(v, v+8, sizeof(*v)*8);
	XorAligned(state, v, sizeof(*v)*8);
}

static const uint64_t k512[]={
	0x243f6a8885a308d3, 0x13198a2e03707344,
	0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c,
	0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac,
	0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7,
	0x0801f2e2858efc16, 0x636920d871574e69
};

drew::BLAKE512::BLAKE512()
{
	Reset();
}

void drew::BLAKE512::Reset()
{
	m_hash[0] = 0x6a09e667f3bcc908;
	m_hash[1] = 0xbb67ae8584caa73b;
	m_hash[2] = 0x3c6ef372fe94f82b;
	m_hash[3] = 0xa54ff53a5f1d36f1;
	m_hash[4] = 0x510e527fade682d1;
	m_hash[5] = 0x9b05688c2b3e6c1f;
	m_hash[6] = 0x1f83d9abfb41bd6b;
	m_hash[7] = 0x5be0cd19137e2179;
	Initialize();
}

drew::BLAKE384::BLAKE384()
{
	Reset();
}

void drew::BLAKE384::Reset()
{
	m_hash[0] = 0xcbbb9d5dc1059ed8;
	m_hash[1] = 0x629a292a367cd507;
	m_hash[2] = 0x9159015a3070dd17;
	m_hash[3] = 0x152fecd8f70e5939;
	m_hash[4] = 0x67332667ffc00b31;
	m_hash[5] = 0x8eb44a8768581511;
	m_hash[6] = 0xdb0c2e0d64f98fa7;
	m_hash[7] = 0x47b5481dbefa4fa4;
	Initialize();
}

inline void drew::BLAKE512Transform::G(uint64_t &a, uint64_t &b, uint64_t &c,
		uint64_t &d, int r, int i, const uint64_t *m)
{
	a += b + (m[sigma[r][i]] ^ k512[sigma[r][i+1]]);
	d = RotateRight(d ^ a, 32);
	c += d;
	b = RotateRight(b ^ c, 25);
	a += b + (m[sigma[r][i+1]] ^ k512[sigma[r][i]]);
	d = RotateRight(d ^ a, 16);
	c += d;
	b = RotateRight(b ^ c, 11);
}

inline void drew::BLAKE512Transform::Round(uint64_t *v, int r,
		const uint64_t *m)
{
	G(v[ 0], v[ 4], v[ 8], v[12], r,  0, m);
	G(v[ 1], v[ 5], v[ 9], v[13], r,  2, m);
	G(v[ 2], v[ 6], v[10], v[14], r,  4, m);
	G(v[ 3], v[ 7], v[11], v[15], r,  6, m);

	G(v[ 0], v[ 5], v[10], v[15], r,  8, m);
	G(v[ 1], v[ 6], v[11], v[12], r, 10, m);
	G(v[ 2], v[ 7], v[ 8], v[13], r, 12, m);
	G(v[ 3], v[ 4], v[ 9], v[14], r, 14, m);
}

void drew::BLAKE512Transform::Transform(uint64_t *state, const uint8_t *block,
		const uint64_t *lenctr)
{
	uint64_t v[16] ALIGNED_T;
	uint64_t m[16];
	uint64_t len[2];

	E::Copy(m, block, sizeof(m));

	len[1] = (lenctr[1]<<3)|(lenctr[0]>>((sizeof(lenctr[0])*8)-3));
	len[0] = lenctr[0]<<3;

	memcpy(v, state, sizeof(*v)*8);
	v[ 8] = 0x243f6a8885a308d3;
	v[ 9] = 0x13198a2e03707344;
	v[10] = 0xa4093822299f31d0;
	v[11] = 0x082efa98ec4e6c89;
	v[12] = 0x452821e638d01377 ^ len[0];
	v[13] = 0xbe5466cf34e90c6c ^ len[0];
	v[14] = 0xc0ac29b7c97c50dd ^ len[1];
	v[15] = 0x3f84d5b5b5470917 ^ len[1];

	Round(v, 0, m);
	Round(v, 1, m);
	Round(v, 2, m);
	Round(v, 3, m);
	Round(v, 4, m);
	Round(v, 5, m);
	Round(v, 6, m);
	Round(v, 7, m);
	Round(v, 8, m);
	Round(v, 9, m);
	Round(v, 0, m);
	Round(v, 1, m);
	Round(v, 2, m);
	Round(v, 3, m);
	Round(v, 4, m);
	Round(v, 5, m);

	XorAligned(v, v+8, sizeof(*v)*8);
	XorAligned(state, v, sizeof(*v)*8);
}

UNHIDE()
