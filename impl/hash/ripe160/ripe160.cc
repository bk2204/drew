/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the RIPEMD-160 message digest algorithm.  It is
 * compatible with OpenBSD's implementation.  The size of the RMD160_CTX struct
 * is not guaranteed compatible, however.  This implementation requires ANSI C.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "ripe160.hh"
#include "testcase.hh"
#include "util.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(rmd160, RIPEMD160)
PLUGIN_DATA_START()
PLUGIN_DATA(rmd160, "RIPEMD-160")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(ripe160)

static int rmd160test(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<RIPEMD160>("", 0).Test("9c1185a5c5e9fc54612808977ee8f548b2258d31");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("a", 1).Test("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("abc", 1).Test("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("message digest", 1).Test("5d0689ef49d2fae572b881b123a85ffa21595f36");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("abcdefghijklmnopqrstuvwxyz", 1).Test("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("b0e20b6e3116640286ed3a87a5713079b21f5189");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("9b752e45573d4b39f4dbd3323cab82bf63326bfb");
	res <<= 1;
	res |= !HashTestCase<RIPEMD160>::MaintenanceTest("73154a71f6286c75073dfba04128de5b074d8cdf");

	return res;
}
}

static inline uint32_t ff(uint32_t x, uint32_t y, uint32_t z)
{
	return x^y^z;
}
static inline uint32_t gg(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y)|((~x)&z);
}
static inline uint32_t hh(uint32_t x, uint32_t y, uint32_t z)
{
	return (x|~y)^z;
}
static inline uint32_t ii(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&z)|((~z)&y);
}
static inline uint32_t jj(uint32_t x, uint32_t y, uint32_t z)
{
	return x^(y|~z);
}

static const unsigned r[]={
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	 7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	 3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	 1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	 4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};
static const unsigned rp[]={
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};
static const unsigned s[]={
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};
static const unsigned sp[]={
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

drew::RIPEMD160::RIPEMD160()
{
	Reset();
}

void drew::RIPEMD160::Reset()
{
	m_hash[0] = 0x67452301;
	m_hash[1] = 0xefcdab89;
	m_hash[2] = 0x98badcfe;
	m_hash[3] = 0x10325476;
	m_hash[4] = 0xc3d2e1f0;
	Initialize();
}

#define STD(a, b, c, d, e) a=e; e=d; d=RotateLeft(c, 10); c=b; b=t;
#define OP(f, r, s, k, a, b, c, d, e) \
	t=RotateLeft(a+f(b, c, d)+blk[r[i]]+k, s[i])+e; \
	STD(a, b, c, d, e);

void drew::RIPEMD160::Transform(quantum_t *state, const uint8_t *block)
{
	uint32_t buf[block_size/sizeof(uint32_t)];
	const uint32_t *blk;
	size_t i;
	uint32_t a, b, c, d, e, aa, bb, cc, dd, ee, t;

	a = aa = state[0];
	b = bb = state[1];
	c = cc = state[2];
	d = dd = state[3];
	e = ee = state[4];

	blk = endian_t::CopyIfNeeded(buf, block, block_size);

	for (i=0; i<16; i++) {
		OP(ff,  r,  s, 0x00000000,  a,  b,  c,  d,  e);
		OP(jj, rp, sp, 0x50a28be6, aa, bb, cc, dd, ee);
	}
	for (i=16; i<32; i++) {
		OP(gg,  r,  s, 0x5a827999,  a,  b,  c,  d,  e);
		OP(ii, rp, sp, 0x5c4dd124, aa, bb, cc, dd, ee);
	}
	for (i=32; i<48; i++) {
		OP(hh,  r,  s, 0x6ed9eba1,  a,  b,  c,  d,  e);
		OP(hh, rp, sp, 0x6d703ef3, aa, bb, cc, dd, ee);
	}
	for (i=48; i<64; i++) {
		OP(ii,  r,  s, 0x8f1bbcdc,  a,  b,  c,  d,  e);
		OP(gg, rp, sp, 0x7a6d76e9, aa, bb, cc, dd, ee);
	}
	for (i=64; i<80; i++) {
		OP(jj,  r,  s, 0xa953fd4e,  a,  b,  c,  d,  e);
		OP(ff, rp, sp, 0x00000000, aa, bb, cc, dd, ee);
	}

	t = state[1] + c + dd;
	state[1] = state[2] + d + ee;
	state[2] = state[3] + e + aa;
	state[3] = state[4] + a + bb;
	state[4] = state[0] + b + cc;
	state[0] = t;
}
