/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the SHA1 and SHA0 message digest algorithms.  This
 * implementation requires ISO C++.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "sha1.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(sha1, drew::SHA1)
PLUGIN_STRUCTURE(sha0, drew::SHA0)
PLUGIN_DATA_START()
PLUGIN_DATA(sha1, "SHA-1")
PLUGIN_DATA(sha0, "SHA-0")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

static int sha1test(void *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<SHA1>("", 0).Test("da39a3ee5e6b4b0d3255bfef95601890afd80709");
	res <<= 1;
	res |= !HashTestCase<SHA1>("a", 1).Test("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
	res <<= 1;
	res |= !HashTestCase<SHA1>("abc", 1).Test("a9993e364706816aba3e25717850c26c9cd0d89d");
	res <<= 1;
	res |= !HashTestCase<SHA1>("message digest", 1).Test("c12252ceda8be8994d5fa0290a47231c1d16aae3");
	res <<= 1;
	res |= !HashTestCase<SHA1>("abcdefghijklmnopqrstuvwxyz", 1).Test("32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
	res <<= 1;
	res |= !HashTestCase<SHA1>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("761c457bf73b14d27e9e9265c46f4b4dda11f940");
	res <<= 1;
	res |= !HashTestCase<SHA1>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("50abf5706a150990a08b2c5ea40fa0e585554732");
	res <<= 1;
	res |= !HashTestCase<SHA1>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	res <<= 1;
	res |= !HashTestCase<SHA1>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("34aa973cd4c4daa4f61eeb2bdbad27316534016f");

	return res;
}

static int sha0test(void *)
{
	int res = 0;

	using namespace drew;
	
	//res |= !HashTestCase<SHA0>("", 0).Test("da39a3ee5e6b4b0d3255bfef95601890afd80709");
	//res <<= 1;
	//res |= !HashTestCase<SHA0>("a", 1).Test("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
	//res <<= 1;
	res |= !HashTestCase<SHA0>("abc", 1).Test("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
	//res <<= 1;
	//res |= !HashTestCase<SHA0>("message digest", 1).Test("c12252ceda8be8994d5fa0290a47231c1d16aae3");
	//res <<= 1;
	//res |= !HashTestCase<SHA0>("abcdefghijklmnopqrstuvwxyz", 1).Test("32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
	//res <<= 1;
	//res |= !HashTestCase<SHA0>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("761c457bf73b14d27e9e9265c46f4b4dda11f940");
	//res <<= 1;
	//res |= !HashTestCase<SHA0>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("50abf5706a150990a08b2c5ea40fa0e585554732");

	return res;
}
}

static inline uint32_t ff(uint32_t x, uint32_t y, uint32_t z)
{
	return (z^(x&(y^z)))+0x5a827999;
}
static inline uint32_t gg(uint32_t x, uint32_t y, uint32_t z)
{
	return (x^y^z)+0x6ed9eba1;
}
static inline uint32_t hh(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x&y)|(z&(x|y)))+0x8f1bbcdc;
}
static inline uint32_t ii(uint32_t x, uint32_t y, uint32_t z)
{
	return (x^y^z)+0xca62c1d6;
}

/* 32-bit rotate-left. */
static inline uint32_t ROL(uint32_t x, int n)
{
	return ((x<<n)|(x>>(32-n)));
}

template<int Rotate>
drew::SHA<Rotate>::SHA()
{
	m_hash[0] = 0x67452301;
	m_hash[1] = 0xefcdab89;
	m_hash[2] = 0x98badcfe;
	m_hash[3] = 0x10325476;
	m_hash[4] = 0xc3d2e1f0;
	Initialize();
}

#define OP(f, g, a, b, c, d, e) \
	e+=ROL(a, 5)+f(b, c, d)+g; b=ROL(b, 30);
#define EXPANSION(i) \
	(blk[(i)&15]=ROL(blk[((i)+13)&15]^blk[((i)+8)&15]^blk[((i)+2)&15]^blk[(i)&15],Rotate))

/* This implementation uses a circular buffer to create the expansions of blk.
 * While it appears that this would be slower, it instead is significantly
 * faster (174 MiB/s vs. 195 MiB/s).
 */
template<int Rotate>
void drew::SHA<Rotate>::Transform(quantum_t *state, const uint8_t *block)
{
	uint32_t blk[block_size/sizeof(uint32_t)];
	size_t i;
	uint32_t a, b, c, d, e;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	endian_t end;
	end(blk, block, block_size);

	OP(ff, blk[ 0], a, b, c, d, e);
	OP(ff, blk[ 1], e, a, b, c, d);
	OP(ff, blk[ 2], d, e, a, b, c);
	OP(ff, blk[ 3], c, d, e, a, b);
	OP(ff, blk[ 4], b, c, d, e, a);
	OP(ff, blk[ 5], a, b, c, d, e);
	OP(ff, blk[ 6], e, a, b, c, d);
	OP(ff, blk[ 7], d, e, a, b, c);
	OP(ff, blk[ 8], c, d, e, a, b);
	OP(ff, blk[ 9], b, c, d, e, a);
	OP(ff, blk[10], a, b, c, d, e);
	OP(ff, blk[11], e, a, b, c, d);
	OP(ff, blk[12], d, e, a, b, c);
	OP(ff, blk[13], c, d, e, a, b);
	OP(ff, blk[14], b, c, d, e, a);
	OP(ff, blk[15], a, b, c, d, e);
	OP(ff, EXPANSION(16), e, a, b, c, d);
	OP(ff, EXPANSION(17), d, e, a, b, c);
	OP(ff, EXPANSION(18), c, d, e, a, b);
	OP(ff, EXPANSION(19), b, c, d, e, a);
	for (i=20; i<40; i+=5) {
		OP(gg, EXPANSION(i  ), a, b, c, d, e);
		OP(gg, EXPANSION(i+1), e, a, b, c, d);
		OP(gg, EXPANSION(i+2), d, e, a, b, c);
		OP(gg, EXPANSION(i+3), c, d, e, a, b);
		OP(gg, EXPANSION(i+4), b, c, d, e, a);
	}
	for (i=40; i<60; i+=5) {
		OP(hh, EXPANSION(i  ), a, b, c, d, e);
		OP(hh, EXPANSION(i+1), e, a, b, c, d);
		OP(hh, EXPANSION(i+2), d, e, a, b, c);
		OP(hh, EXPANSION(i+3), c, d, e, a, b);
		OP(hh, EXPANSION(i+4), b, c, d, e, a);
	}
	for (i=60; i<80; i+=5) {
		OP(ii, EXPANSION(i  ), a, b, c, d, e);
		OP(ii, EXPANSION(i+1), e, a, b, c, d);
		OP(ii, EXPANSION(i+2), d, e, a, b, c);
		OP(ii, EXPANSION(i+3), c, d, e, a, b);
		OP(ii, EXPANSION(i+4), b, c, d, e, a);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}
