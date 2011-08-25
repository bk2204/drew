/*-
 * Copyright © 2011 brian m. carlson
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

#include "keccak.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

HIDE()
extern "C" {
PLUGIN_STRUCTURE2(keccak, Keccak)
PLUGIN_DATA_START()
PLUGIN_DATA(keccak, "Keccak")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(keccak)

static int keccak_get_digest_size(const drew_param_t *param)
{
	size_t digestsizeval = 0, result = 0;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!p->name)
			continue;
		// This is in bytes.
		if (!digestsizeval && !strcmp(p->name, "digestSize"))
			digestsizeval = p->param.number;
	}
	if (digestsizeval)
		result = digestsizeval;
	if (!result)
		return -DREW_ERR_MORE_INFO;
	return result;
}

static int keccakinfo(int op, void *p)
{
	using namespace drew;
	const drew_param_t *param = reinterpret_cast<const drew_param_t *>(p);
	const drew_hash_t *ctx = reinterpret_cast<const drew_hash_t *>(p);
	switch (op) {
		case DREW_HASH_VERSION:
			return 2;
		case DREW_HASH_QUANTUM:
			return sizeof(Keccak::quantum_t);
		case DREW_HASH_SIZE:
			return keccak_get_digest_size(param);
		case DREW_HASH_BLKSIZE:
			if (p)
				return ((const Keccak *)ctx->ctx)->GetBlockSize();
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE:
			if (p)
				return ((const Keccak *)ctx->ctx)->GetBlockSize();
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_INTSIZE:
			return sizeof(Keccak);
		case DREW_HASH_ENDIAN:
			return Keccak::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static int keccakinit(drew_hash_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param)
{
	using namespace drew;
	Keccak *p;
	int size = keccak_get_digest_size(param);
	if (size <= 0)
		return size;
	if (flags & DREW_HASH_FIXED)
		p = new (ctx->ctx) Keccak(size);
	else
		p = new Keccak(size);
	ctx->ctx = p;
	ctx->functbl = &keccakfunctbl;
	return 0;
}

static int keccaktest(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	typedef VariableSizedHashTestCase<Keccak, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<Keccak, 256/8> TestCase256;
	typedef VariableSizedHashTestCase<Keccak, 384/8> TestCase384;
	typedef VariableSizedHashTestCase<Keccak, 512/8> TestCase512;

	static const uint8_t test[] = {
		0x83, 0xaf, 0x34, 0x27, 0x9c, 0xcb, 0x54, 0x30,
		0xfe, 0xbe, 0xc0, 0x7a, 0x81, 0x95, 0x0d, 0x30,
		0xf4, 0xb6, 0x6f, 0x48, 0x48, 0x26, 0xaf, 0xee,
		0x74, 0x56, 0xf0, 0x07, 0x1a, 0x51, 0xe1, 0xbb,
		0xc5, 0x55, 0x70, 0xb5, 0xcc, 0x7e, 0xc6, 0xf9,
		0x30, 0x9c, 0x17, 0xbf, 0x5b, 0xef, 0xdd, 0x7c,
		0x6b, 0xa6, 0xe9, 0x68, 0xcf, 0x21, 0x8a, 0x2b,
		0x34, 0xbd, 0x5c, 0xf9, 0x27, 0xab, 0x84, 0x6e,
		0x38, 0xa4, 0x0b, 0xbd, 0x81, 0x75, 0x9e, 0x9e,
		0x33, 0x38, 0x10, 0x16, 0xa7, 0x55, 0xf6, 0x99,
		0xdf, 0x35, 0xd6, 0x60, 0x00, 0x7b, 0x5e, 0xad,
		0xf2, 0x92, 0xfe, 0xef, 0xb7, 0x35, 0x20, 0x7e,
		0xbf, 0x70, 0xb5, 0xbd, 0x17, 0x83, 0x4f, 0x7b,
		0xfa, 0x0e, 0x16, 0xcb, 0x21, 0x9a, 0xd4, 0xaf,
		0x52, 0x4a, 0xb1, 0xea, 0x37, 0x33, 0x4a, 0xa6,
		0x64, 0x35, 0xe5, 0xd3, 0x97, 0xfc, 0x0a, 0x06,
		0x5c, 0x41, 0x1e, 0xbb, 0xce, 0x32, 0xc2, 0x40,
		0xb9, 0x04, 0x76, 0xd3, 0x07, 0xce, 0x80, 0x2e,
		0xc8, 0x2c, 0x1c, 0x49, 0xbc, 0x1b, 0xec, 0x48,
		0xc0, 0x67, 0x5e, 0xc2, 0xa6, 0xc6, 0xf3, 0xed,
		0x3e, 0x5b, 0x74, 0x1d, 0x13, 0x43, 0x70, 0x95,
		0x70, 0x7c, 0x56, 0x5e, 0x10, 0xd8, 0xa2, 0x0b,
		0x8c, 0x20, 0x46, 0x8f, 0xf9, 0x51, 0x4f, 0xcf,
		0x31, 0xb4, 0x24, 0x9c, 0xd8, 0x2d, 0xce, 0xe5,
		0x8c, 0x0a, 0x2a, 0xf5, 0x38, 0xb2, 0x91, 0xa8,
		0x7e, 0x33, 0x90, 0xd7, 0x37, 0x19, 0x1a, 0x07,
		0x48, 0x4a, 0x5d, 0x3f, 0x3f, 0xb8, 0xc8, 0xf1,
		0x5c, 0xe0, 0x56, 0xe5, 0xe5, 0xf8, 0xfe, 0xbe,
		0x5e, 0x1f, 0xb5, 0x9d, 0x67, 0x40, 0x98, 0x0a,
		0xa0, 0x6c, 0xa8, 0xa0, 0xc2, 0x0f, 0x57, 0x12,
		0xb4, 0xcd, 0xe5, 0xd0, 0x32, 0xe9, 0x2a, 0xb8,
		0x9f, 0x0a, 0xe1
	};

	res |= !TestCase224(test, sizeof(test), 1).Test("ecde4d6eb0cf28010b45d0d310e7d05f08b80afc44b8a359be7e1923");
	res <<= 1;
	res |= !TestCase224("", 0).Test("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd");
	res <<= 1;
	res |= !TestCase256("", 0).Test("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	res <<= 1;
	res |= !TestCase384("", 0).Test("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
	res <<= 1;
	res |= !TestCase512("", 0).Test("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");

	return res;
}

}

typedef drew::Keccak::endian_t E;

drew::Keccak::Keccak(size_t t_) : m_c(t_*2), m_r(200-m_c)
{
	Reset();
}

inline static void dump(const char *s, uint64_t a[5][5])
{
#if 0
	for (size_t i = 0; i < 5; i++)
		printf("%s%d: %016lx %016lx %016lx %016lx %016lx\n", s, i, a[0][i],
				a[1][i], a[2][i], a[3][i], a[4][i]);
#endif
}

inline static void theta(uint64_t a[5][5])
{
	uint64_t c[5], d[5];

	for (size_t i = 0; i < 5; i++)
		c[i] = a[i][0] ^ a[i][1] ^ a[i][2] ^ a[i][3] ^ a[i][4];
	for (size_t i = 0; i < 5; i++) {
		d[i] = c[(i+4) % 5] ^ RotateLeft(c[(i+1) % 5], 1);
		for (size_t j = 0; j < 5; j++)
			a[i][j] ^= d[i];
	}
}

static const unsigned rr[5][5] = {
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14}
};

inline static void chirhopi(uint64_t a[5][5])
{
	uint64_t b[5][5];

	for (size_t i = 0; i < 5; i++)
		for (size_t j = 0; j < 5; j++)
			b[j][((2*i)+(3*j))%5] = RotateLeft(a[i][j], rr[i][j]);

	for (size_t i = 0; i < 5; i++)
		for (size_t j = 0; j < 5; j++)
			a[i][j] = b[i][j] ^ ((~b[(i+1)%5][j]) & b[(i+2)%5][j]);
}

inline static void iota(uint64_t a[5][5], uint64_t k)
{
	a[0][0] ^= k;
}

inline static void round(uint64_t a[5][5], uint64_t k)
{
	theta(a);
	chirhopi(a);
	iota(a, k);
}

static const uint64_t rc[] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008
};

static void keccak_f(uint64_t state[5][5])
{
	dump("s", state);
	for (size_t i = 0; i < 24; i++)
		round(state, rc[i]);
	dump("e", state);
}

// This is not very useful, but is required for the API.
void drew::Keccak::Transform(uint64_t state[5][5], const uint8_t *block)
{
	return Transform(state, block, (1600 - 576) / 8);
}

void drew::Keccak::Transform(uint64_t state[5][5], const uint8_t *block,
		size_t r)
{
	uint64_t blk[1152/64];
	const uint64_t *b;
	const size_t nwords = r / sizeof(uint64_t);
	b = E::CopyIfNeeded(blk, block, r);
	for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
		for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
			state[x][y] ^= b[x + (5*y)];
	keccak_f(state);
}

void drew::Keccak::GetDigest(uint8_t *digest, bool nopad)
{
	if (!nopad)
		Pad();

	const size_t nwords = m_r / sizeof(uint64_t);
	const size_t len = m_c / 2;
	uint8_t *d = digest;
	for (size_t i = 0; i < len; i += m_r, d += m_r) {
		uint64_t b[1152/64];
		for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
			for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
				b[x + (5*y)] = m_hash[x][y];
		E::CopyCarefully(d, b, std::min(m_r, len - i));
	}
}
UNHIDE()