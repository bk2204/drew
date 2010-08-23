/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the MD4 message digest algorithm.  This implementation
 * requires ISO C++.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "md4.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(md4, drew::MD4)
PLUGIN_DATA_START()
PLUGIN_DATA(md4, "MD4")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

static int md4test(void *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<MD4>("", 0).Test("31d6cfe0d16ae931b73c59d7e0c089c0");
	res <<= 1;
	res |= !HashTestCase<MD4>("a", 1).Test("bde52cb31de33e46245e05fbdbd6fb24");
	res <<= 1;
	res |= !HashTestCase<MD4>("abc", 1).Test("a448017aaf21d8525fc10ae87aa6729d");
	res <<= 1;
	res |= !HashTestCase<MD4>("message digest", 1).Test("d9130a8164549fe818874806e1c7014b");
	res <<= 1;
	res |= !HashTestCase<MD4>("abcdefghijklmnopqrstuvwxyz", 1).Test("d79e1c308aa5bbcdeea8ed63df412da9");
	res <<= 1;
	res |= !HashTestCase<MD4>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("043f8582f241db351ce627e153e7f0e4");
	res <<= 1;
	res |= !HashTestCase<MD4>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("e33b4ddc9c38f2199c3e7b164fcc0536");

	return res;
}
}

#define F(x, y, z) ((z)^((x)&((y)^(z)))) /*(((x)&(y))|((~(x))&(z)))*/
#define G(x, y, z) (((x)&(y))|((z)&((x)|(y))))
#define H(x, y, z) ((x)^(y)^(z))

/* 32-bit rotate-left. */
static inline uint32_t ROL(uint32_t x, int n)
{
	return ((x<<n)|(x>>(32-n)));
}

drew::MD4::MD4()
{
	m_hash[0] = 0x67452301;
	m_hash[1] = 0xefcdab89;
	m_hash[2] = 0x98badcfe;
	m_hash[3] = 0x10325476;
	Initialize();
}

#define OP(a, b, c, d, f, k, s, x) a=ROL((a+f(b,c,d)+blk[k]+x), s)
#define FF(a, b, c, d, k, s) OP(a, b, c, d, F, k, s, 0)
#define GG(a, b, c, d, k, s) OP(a, b, c, d, G, k, s, 0x5a827999)
#define HH(a, b, c, d, k, s) OP(a, b, c, d, H, k, s, 0x6ed9eba1)

void drew::MD4::Transform(quantum_t *state, const uint8_t *block)
{
	uint32_t buf[block_size/sizeof(uint32_t)];
	uint32_t a, b, c, d;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	const uint32_t *blk = endian_t::CopyIfNeeded(buf, block, block_size);

	FF(a,b,c,d, 0, 3); FF(d,a,b,c, 1, 7);
	FF(c,d,a,b, 2,11); FF(b,c,d,a, 3,19);
	FF(a,b,c,d, 4, 3); FF(d,a,b,c, 5, 7);
	FF(c,d,a,b, 6,11); FF(b,c,d,a, 7,19);
	FF(a,b,c,d, 8, 3); FF(d,a,b,c, 9, 7);
	FF(c,d,a,b,10,11); FF(b,c,d,a,11,19);
	FF(a,b,c,d,12, 3); FF(d,a,b,c,13, 7);
	FF(c,d,a,b,14,11); FF(b,c,d,a,15,19);

	GG(a,b,c,d, 0, 3); GG(d,a,b,c, 4, 5);
	GG(c,d,a,b, 8, 9); GG(b,c,d,a,12,13);
	GG(a,b,c,d, 1, 3); GG(d,a,b,c, 5, 5);
	GG(c,d,a,b, 9, 9); GG(b,c,d,a,13,13);
	GG(a,b,c,d, 2, 3); GG(d,a,b,c, 6, 5);
	GG(c,d,a,b,10, 9); GG(b,c,d,a,14,13);
	GG(a,b,c,d, 3, 3); GG(d,a,b,c, 7, 5);
	GG(c,d,a,b,11, 9); GG(b,c,d,a,15,13);

	HH(a,b,c,d, 0, 3); HH(d,a,b,c, 8, 9);
	HH(c,d,a,b, 4,11); HH(b,c,d,a,12,15);
	HH(a,b,c,d, 2, 3); HH(d,a,b,c,10, 9);
	HH(c,d,a,b, 6,11); HH(b,c,d,a,14,15);
	HH(a,b,c,d, 1, 3); HH(d,a,b,c, 9, 9);
	HH(c,d,a,b, 5,11); HH(b,c,d,a,13,15);
	HH(a,b,c,d, 3, 3); HH(d,a,b,c,11, 9);
	HH(c,d,a,b, 7,11); HH(b,c,d,a,15,15);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
