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
template<class T>
static int keccak_test(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	typedef VariableSizedHashTestCase<T, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<T, 256/8> TestCase256;
	typedef VariableSizedHashTestCase<T, 384/8> TestCase384;
	typedef VariableSizedHashTestCase<T, 512/8> TestCase512;

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
	if (result > (512/8))
		return -DREW_ERR_INVALID;
	return result;
}

template<class T>
static int keccak_info(int op, void *p)
{
	using namespace drew;
	const drew_param_t *param = reinterpret_cast<const drew_param_t *>(p);
	const drew_hash_t *ctx = reinterpret_cast<const drew_hash_t *>(p);
	switch (op) {
		case DREW_HASH_VERSION:
			return 3;
		case DREW_HASH_SIZE:
			return keccak_get_digest_size(param);
		case DREW_HASH_BLKSIZE:
			if (p)
				return ((const T *)ctx->ctx)->GetBlockSize();
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE:
			return 1600/8;
		case DREW_HASH_INTSIZE:
			return sizeof(T);
		case DREW_HASH_ENDIAN:
			return T::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static const int hash_sizes[] = {
	224/8, 256/8, 384/8, 512/8
};

static const int block_sizes[] = {
	224/8, 256/8, 384/8, 512/8
};

static const int buffer_sizes[] = {
	5*5*(64/8)
};

template<class T>
static int keccak_info2(const drew_hash_t *ctxt, int op, drew_param_t *outp,
		const drew_param_t *inp)
{
	using namespace drew;
	switch (op) {
		case DREW_HASH_VERSION:
			return 3;
		case DREW_HASH_SIZE_LIST:
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "digestSize")) {
					p->param.array.ptr = (void *)hash_sizes;
					p->param.array.len = DIM(hash_sizes);
				}
			return 0;
		case DREW_HASH_BLKSIZE_LIST:
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "blockSize")) {
					p->param.array.ptr = (void *)block_sizes;
					p->param.array.len = DIM(block_sizes);
				}
			return 0;
		case DREW_HASH_BUFSIZE_LIST:
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "bufferSize")) {
					p->param.array.ptr = (void *)buffer_sizes;
					p->param.array.len = DIM(buffer_sizes);
				}
			return 0;
		case DREW_HASH_SIZE_CTX:
			if (ctxt && ctxt->ctx) {
				const T *ctx = (const T *)ctxt->ctx;
				return ctx->GetBlockSize();
			}	
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BLKSIZE_CTX:
			if (ctxt && ctxt->ctx) {
				const T *ctx = (const T *)ctxt->ctx;
				return ctx->GetBlockSize();
			}	
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE_CTX:
			return 1600/8;
		case DREW_HASH_INTSIZE:
			return sizeof(T);
		case DREW_HASH_ENDIAN:
			return T::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

template<class T>
static int keccak_init(drew_hash_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param, const drew_hash_functbl_t *tbl)
{
	T *p;
	int size = keccak_get_digest_size(param);
	if (size <= 0)
		return size;
	if (flags & DREW_HASH_FIXED)
		p = new (ctx->ctx) T(size);
	else
		p = new T(size);
	ctx->ctx = p;
	ctx->functbl = tbl;
	return 0;
}

extern "C" {
PLUGIN_STRUCTURE2(keccak, Keccak)
PLUGIN_STRUCTURE2(keccakwln, KeccakWithLimitedNots)
PLUGIN_DATA_START()
PLUGIN_DATA(keccak, "Keccak")
PLUGIN_DATA(keccakwln, "Keccak")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(keccak)

static int keccakinfo(int op, void *p)
{
	return keccak_info<drew::Keccak>(op, p);
}

static int keccakinfo2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::Keccak>(ctx, op, out, in);
}

static int keccakinit(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::Keccak>(ctx, flags, ldr, param, &keccakfunctbl);
}

static int keccaktest(void *p, const drew_loader_t *ldr)
{
	return keccak_test<drew::Keccak>(p, ldr);
}

static int keccakwlninfo(int op, void *p)
{
	return keccak_info<drew::KeccakWithLimitedNots>(op, p);
}

static int keccakwlninfo2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::KeccakWithLimitedNots>(ctx, op, out, in);
}

static int keccakwlninit(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::KeccakWithLimitedNots>(ctx, flags, ldr, param,
			&keccakwlnfunctbl);
}

static int keccakwlntest(void *p, const drew_loader_t *ldr)
{
	return keccak_test<drew::KeccakWithLimitedNots>(p, ldr);
}

}

typedef drew::Keccak::endian_t E;

drew::Keccak::Keccak(size_t t_) : m_c(t_*2), m_r(200-m_c)
{
	Reset();
}

drew::KeccakWithLimitedNots::KeccakWithLimitedNots(size_t t_)
{
	m_c = t_ * 2;
	m_r = 200 - m_c;
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
	uint64_t c[5], d;

	for (size_t i = 0; i < 5; i++)
		c[i] = a[i][0] ^ a[i][1] ^ a[i][2] ^ a[i][3] ^ a[i][4];
	for (size_t i = 0; i < 5; i++) {
		d = c[(i+4) % 5] ^ RotateLeft(c[(i+1) % 5], 1);
		for (size_t j = 0; j < 5; j++)
			a[i][j] ^= d;
	}
}

static const unsigned rr[5][5] = {
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14}
};

inline static void rhopi(uint64_t b[5][5], const uint64_t a[5][5])
{
	b[0][((2*0)+(3*0))%5] = a[0][0];
	b[0][((2*1)+(3*0))%5] = RotateLeft(a[1][0],  1);
	b[0][((2*2)+(3*0))%5] = RotateLeft(a[2][0], 62);
	b[0][((2*3)+(3*0))%5] = RotateLeft(a[3][0], 28);
	b[0][((2*4)+(3*0))%5] = RotateLeft(a[4][0], 27);

	b[1][((2*0)+(3*1))%5] = RotateLeft(a[0][1], 36);
	b[1][((2*1)+(3*1))%5] = RotateLeft(a[1][1], 44);
	b[1][((2*2)+(3*1))%5] = RotateLeft(a[2][1],  6);
	b[1][((2*3)+(3*1))%5] = RotateLeft(a[3][1], 55);
	b[1][((2*4)+(3*1))%5] = RotateLeft(a[4][1], 20);

	b[2][((2*0)+(3*2))%5] = RotateLeft(a[0][2],  3);
	b[2][((2*1)+(3*2))%5] = RotateLeft(a[1][2], 10);
	b[2][((2*2)+(3*2))%5] = RotateLeft(a[2][2], 43);
	b[2][((2*3)+(3*2))%5] = RotateLeft(a[3][2], 25);
	b[2][((2*4)+(3*2))%5] = RotateLeft(a[4][2], 39);

	b[3][((2*0)+(3*3))%5] = RotateLeft(a[0][3], 41);
	b[3][((2*1)+(3*3))%5] = RotateLeft(a[1][3], 45);
	b[3][((2*2)+(3*3))%5] = RotateLeft(a[2][3], 15);
	b[3][((2*3)+(3*3))%5] = RotateLeft(a[3][3], 21);
	b[3][((2*4)+(3*3))%5] = RotateLeft(a[4][3],  8);

	b[4][((2*0)+(3*4))%5] = RotateLeft(a[0][4], 18);
	b[4][((2*1)+(3*4))%5] = RotateLeft(a[1][4],  2);
	b[4][((2*2)+(3*4))%5] = RotateLeft(a[2][4], 61);
	b[4][((2*3)+(3*4))%5] = RotateLeft(a[3][4], 56);
	b[4][((2*4)+(3*4))%5] = RotateLeft(a[4][4], 14);
}

template<int T>
inline static void chi(uint64_t a[5][5], const uint64_t b[5][5])
{
	for (size_t j = 0; j < 5; j++) {
		// If the processor has an and-not instruction, such as SPARC or ARM,
		// then the compiler will adjust this appropriately to use that
		// instruction.  (We hope.)
		a[0][j] = b[0][j] ^ ((~b[1][j]) & b[2][j]);
		a[1][j] = b[1][j] ^ ((~b[2][j]) & b[3][j]);
		a[2][j] = b[2][j] ^ ((~b[3][j]) & b[4][j]);
		a[3][j] = b[3][j] ^ ((~b[4][j]) & b[0][j]);
		a[4][j] = b[4][j] ^ ((~b[0][j]) & b[1][j]);
	}
}

template<>
inline void chi<1>(uint64_t a[5][5], const uint64_t b[5][5])
{
	// This version is used when the processor does not have an and-not
	// instruction; it reduces the number of nots used by using the lane
	// complementation technique.
	a[0][0] =  b[0][0] ^ ( b[1][0] |  b[2][0]);
	a[0][1] =  b[0][1] ^ ( b[1][1] |  b[2][1]);
	a[0][2] =  b[0][2] ^ ( b[1][2] |  b[2][2]);
	a[0][3] =  b[0][3] ^ ( b[1][3] &  b[2][3]);
	a[0][4] =  b[0][4] ^ (~b[1][4] &  b[2][4]);
	
	a[1][0] =  b[1][0] ^ (~b[2][0] |  b[3][0]);
	a[1][1] =  b[1][1] ^ ( b[2][1] &  b[3][1]);
	a[1][2] =  b[1][2] ^ ( b[2][2] &  b[3][2]);
	a[1][3] =  b[1][3] ^ ( b[2][3] |  b[3][3]);
	a[1][4] = ~b[1][4] ^ ( b[2][4] |  b[3][4]);

	a[2][0] =  b[2][0] ^ ( b[3][0] &  b[4][0]);
	a[2][1] =  b[2][1] ^ ( b[3][1] | ~b[4][1]);
	a[2][2] =  b[2][2] ^ (~b[3][2] &  b[4][2]);
	a[2][3] =  b[2][3] ^ (~b[3][3] |  b[4][3]);
	a[2][4] =  b[2][4] ^ ( b[3][4] &  b[4][4]);

	a[3][0] =  b[3][0] ^ ( b[4][0] |  b[0][0]);
	a[3][1] =  b[3][1] ^ ( b[4][1] |  b[0][1]);
	a[3][2] = ~b[3][2] ^ ( b[4][2] |  b[0][2]);
	a[3][3] = ~b[3][3] ^ ( b[4][3] &  b[0][3]);
	a[3][4] =  b[3][4] ^ ( b[4][4] |  b[0][4]);

	a[4][0] =  b[4][0] ^ ( b[0][0] &  b[1][0]);
	a[4][1] =  b[4][1] ^ ( b[0][1] &  b[1][1]);
	a[4][2] =  b[4][2] ^ ( b[0][2] &  b[1][2]);
	a[4][3] =  b[4][3] ^ ( b[0][3] |  b[1][3]);
	a[4][4] =  b[4][4] ^ ( b[0][4] &  b[1][4]);
}

template<int T>
inline static void chirhopi(uint64_t a[5][5])
{
	uint64_t b[5][5];
	rhopi(b, a);
	chi<T>(a, b);
}

inline static void iota(uint64_t a[5][5], uint64_t k)
{
	a[0][0] ^= k;
}

template<int T>
inline static void round(uint64_t a[5][5], uint64_t k)
{
	theta(a);
	chirhopi<T>(a);
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

template<int T>
static void keccak_f(uint64_t state[5][5])
{
	dump("s", state);
	for (size_t i = 0; i < 24; i += 6) {
		round<T>(state, rc[i+0]);
		round<T>(state, rc[i+1]);
		round<T>(state, rc[i+2]);
		round<T>(state, rc[i+3]);
		round<T>(state, rc[i+4]);
		round<T>(state, rc[i+5]);
	}
	dump("e", state);
}

// This is not very useful, but is required for the API.
void drew::Keccak::Transform(uint64_t state[5][5], const uint8_t *block)
{
	return Transform(state, block, (1600 - 576) / 8);
}

void drew::KeccakWithLimitedNots::Transform(uint64_t state[5][5],
		const uint8_t *block)
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
	keccak_f<0>(state);
}

void drew::Keccak::Reset()
{
	m_len = 0;
	memset(m_buf, 0, sizeof(m_buf));
	memset(m_hash, 0, sizeof(m_hash));
}

void drew::KeccakWithLimitedNots::Reset()
{
	m_len = 0;
	memset(m_buf, 0, sizeof(m_buf));
	memset(m_hash, 0, sizeof(m_hash));
	m_hash[1][0] = ~0;
	m_hash[2][0] = ~0;
	m_hash[3][1] = ~0;
	m_hash[2][2] = ~0;
	m_hash[2][3] = ~0;
	m_hash[0][4] = ~0;
}

void drew::KeccakWithLimitedNots::Transform(uint64_t state[5][5],
		const uint8_t *block, size_t r)
{
	uint64_t blk[1152/64];
	const uint64_t *b;
	const size_t nwords = r / sizeof(uint64_t);
	b = E::CopyIfNeeded(blk, block, r);
	for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
		for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
			state[x][y] ^= b[x + (5*y)];
	keccak_f<1>(state);
}

void drew::Keccak::GetDigest(uint8_t *digest, size_t len, bool nopad)
{
	if (!nopad)
		Pad();

	const size_t nwords = m_r / sizeof(uint64_t);
	uint8_t *d = digest;
	for (size_t i = 0; i < len; i += m_r, d += m_r) {
		uint64_t b[1152/64];
		for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
			for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
				b[x + (5*y)] = m_hash[x][y];
		E::CopyCarefully(d, b, std::min(m_r, len - i));
	}
}

void drew::KeccakWithLimitedNots::GetDigest(uint8_t *digest, size_t len,
		bool nopad)
{
	if (!nopad)
		Pad();

	m_hash[1][0] = ~m_hash[1][0];
	m_hash[2][0] = ~m_hash[2][0];
	m_hash[3][1] = ~m_hash[3][1];
	m_hash[2][2] = ~m_hash[2][2];
	m_hash[2][3] = ~m_hash[2][3];
	m_hash[0][4] = ~m_hash[0][4];
	const size_t nwords = m_r / sizeof(uint64_t);
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
