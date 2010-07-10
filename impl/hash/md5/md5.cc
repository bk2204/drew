#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "md5.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(md5, drew::MD5)
PLUGIN_DATA_START()
PLUGIN_DATA(md5, "MD5")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()
}

#define F(x, y, z) ((z)^((x)&((y)^(z)))) /*(((x)&(y))|((~(x))&(z)))*/
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x)^(y)^(z))
#define I(x, y, z) ((y)^((x)|~(z)))

/* 32-bit rotate-left. */
static inline uint32_t ROL(uint32_t x, int n)
{
	return ((x<<n)|(x>>(32-n)));
}

drew::MD5::MD5()
{
	m_hash[0] = 0x67452301;
	m_hash[1] = 0xefcdab89;
	m_hash[2] = 0x98badcfe;
	m_hash[3] = 0x10325476;
	Initialize();
}

#define OP(a, b, c, d, f, k, s, i) a=b+(ROL((a+f(b,c,d)+blk[k]+i),s))
#define FF(a, b, c, d, k, s, i) OP(a, b, c, d, F, k, s, i)
#define GG(a, b, c, d, k, s, i) OP(a, b, c, d, G, k, s, i)
#define HH(a, b, c, d, k, s, i) OP(a, b, c, d, H, k, s, i)
#define II(a, b, c, d, k, s, i) OP(a, b, c, d, I, k, s, i)

void drew::MD5::Transform(quantum_t *state, const uint8_t *block)
{
	uint32_t blk[block_size/sizeof(uint32_t)];
	uint32_t a, b, c, d;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	endian_t e;
	e(blk, block, block_size);
	FF(a,b,c,d, 0, 7, 0xd76aa478);
	FF(d,a,b,c, 1,12, 0xe8c7b756);
	FF(c,d,a,b, 2,17, 0x242070db);
	FF(b,c,d,a, 3,22, 0xc1bdceee);
	FF(a,b,c,d, 4, 7, 0xf57c0faf);
	FF(d,a,b,c, 5,12, 0x4787c62a);
	FF(c,d,a,b, 6,17, 0xa8304613);
	FF(b,c,d,a, 7,22, 0xfd469501);
	FF(a,b,c,d, 8, 7, 0x698098d8);
	FF(d,a,b,c, 9,12, 0x8b44f7af);
	FF(c,d,a,b,10,17, 0xffff5bb1);
	FF(b,c,d,a,11,22, 0x895cd7be);
	FF(a,b,c,d,12, 7, 0x6b901122);
	FF(d,a,b,c,13,12, 0xfd987193);
	FF(c,d,a,b,14,17, 0xa679438e);
	FF(b,c,d,a,15,22, 0x49b40821);

	GG(a,b,c,d, 1, 5, 0xf61e2562);
	GG(d,a,b,c, 6, 9, 0xc040b340);
	GG(c,d,a,b,11,14, 0x265e5a51);
	GG(b,c,d,a, 0,20, 0xe9b6c7aa);
	GG(a,b,c,d, 5, 5, 0xd62f105d);
	GG(d,a,b,c,10, 9, 0x02441453);
	GG(c,d,a,b,15,14, 0xd8a1e681);
	GG(b,c,d,a, 4,20, 0xe7d3fbc8);
	GG(a,b,c,d, 9, 5, 0x21e1cde6);
	GG(d,a,b,c,14, 9, 0xc33707d6);
	GG(c,d,a,b, 3,14, 0xf4d50d87);
	GG(b,c,d,a, 8,20, 0x455a14ed);
	GG(a,b,c,d,13, 5, 0xa9e3e905);
	GG(d,a,b,c, 2, 9, 0xfcefa3f8);
	GG(c,d,a,b, 7,14, 0x676f02d9);
	GG(b,c,d,a,12,20, 0x8d2a4c8a);

	HH(a,b,c,d, 5, 4, 0xfffa3942);
	HH(d,a,b,c, 8,11, 0x8771f681);
	HH(c,d,a,b,11,16, 0x6d9d6122);
	HH(b,c,d,a,14,23, 0xfde5380c);
	HH(a,b,c,d, 1, 4, 0xa4beea44);
	HH(d,a,b,c, 4,11, 0x4bdecfa9);
	HH(c,d,a,b, 7,16, 0xf6bb4b60);
	HH(b,c,d,a,10,23, 0xbebfbc70);
	HH(a,b,c,d,13, 4, 0x289b7ec6);
	HH(d,a,b,c, 0,11, 0xeaa127fa);
	HH(c,d,a,b, 3,16, 0xd4ef3085);
	HH(b,c,d,a, 6,23, 0x04881d05);
	HH(a,b,c,d, 9, 4, 0xd9d4d039);
	HH(d,a,b,c,12,11, 0xe6db99e5);
	HH(c,d,a,b,15,16, 0x1fa27cf8);
	HH(b,c,d,a, 2,23, 0xc4ac5665);

	II(a,b,c,d, 0, 6, 0xf4292244);
	II(d,a,b,c, 7,10, 0x432aff97);
	II(c,d,a,b,14,15, 0xab9423a7);
	II(b,c,d,a, 5,21, 0xfc93a039);
	II(a,b,c,d,12, 6, 0x655b59c3);
	II(d,a,b,c, 3,10, 0x8f0ccc92);
	II(c,d,a,b,10,15, 0xffeff47d);
	II(b,c,d,a, 1,21, 0x85845dd1);
	II(a,b,c,d, 8, 6, 0x6fa87e4f);
	II(d,a,b,c,15,10, 0xfe2ce6e0);
	II(c,d,a,b, 6,15, 0xa3014314);
	II(b,c,d,a,13,21, 0x4e0811a1);
	II(a,b,c,d, 4, 6, 0xf7537e82);
	II(d,a,b,c,11,10, 0xbd3af235);
	II(c,d,a,b, 2,15, 0x2ad7d2bb);
	II(b,c,d,a, 9,21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
