#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "sha512.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(sha512, drew::SHA512)
PLUGIN_STRUCTURE(sha384, drew::SHA384)
PLUGIN_DATA_START()
PLUGIN_DATA(sha512, "SHA-512")
PLUGIN_DATA(sha384, "SHA-384")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

static int sha512test(void *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<SHA512>("", 0).Test("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
	res <<= 1;
	res |= !HashTestCase<SHA512>("a", 1).Test("1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abc", 1).Test("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	res <<= 1;
	res |= !HashTestCase<SHA512>("message digest", 1).Test("107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdefghijklmnopqrstuvwxyz", 1).Test("4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1");
	res <<= 1;
	res |= !HashTestCase<SHA512>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894");
	res <<= 1;
	res |= !HashTestCase<SHA512>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
	res <<= 1;
	res |= !HashTestCase<SHA512>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

	return res;
}

static int sha384test(void *)
{
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<SHA384>("", 0).Test("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
	res <<= 1;
	res |= !HashTestCase<SHA384>("a", 1).Test("54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abc", 1).Test("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
	res <<= 1;
	res |= !HashTestCase<SHA384>("message digest", 1).Test("473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdefghijklmnopqrstuvwxyz", 1).Test("feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4");
	res <<= 1;
	res |= !HashTestCase<SHA384>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84");
	res <<= 1;
	res |= !HashTestCase<SHA384>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
	res <<= 1;
	res |= !HashTestCase<SHA384>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");

	return res;
}
}

/* 32-bit rotate-right. */
static inline uint64_t ROR(uint64_t x, int n)
{
	return ((x>>n)|(x<<(64-n)));
}

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	return (z^(x&(y^z)));
}
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
	return (x&y)^(x&z)^(y&z);
}
static inline uint64_t S0(uint64_t x)
{
	return ROR(x, 28)^ROR(x, 34)^ROR(x, 39);
}
static inline uint64_t S1(uint64_t x)
{
	return ROR(x, 14)^ROR(x, 18)^ROR(x, 41);
}
static inline uint64_t s0(uint64_t x)
{
	return ROR(x, 1)^ROR(x, 8)^(x>>7);
}
static inline uint64_t s1(uint64_t x)
{
	return ROR(x, 19)^ROR(x, 61)^(x>>6);
}

static const uint64_t k[]={
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

drew::SHA512::SHA512()
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

drew::SHA384::SHA384()
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

#define ROUND(a, b, c, d, e, f, g, h, k, blk) \
	h+=S1(e)+Ch(e, f, g)+k+blk; \
	d+=h; \
	h+=S0(a)+Maj(a, b, c)

#define ROUND2(a, b, c, d, e, f, g, h, k, i) \
	blk[i] = s1(blk[i-2]) + blk[i-7] + s0(blk[i-15]) + blk[i-16]; \
	ROUND(a, b, c, d, e, f, g, h, k, blk[i]); \

void drew::SHA512Transform::Transform(uint64_t *state, const uint8_t *block)
{
	// This is normally defined automatically by Hash.
	const size_t block_size = 128;
	const size_t words = block_size / sizeof(uint64_t);
	uint64_t blk[80];
	size_t i;
	uint64_t a, b, c, d, e, f, g, h;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	endian end;
	end(blk, block, block_size);

	for (i = 0; i < words; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, k[i  ], blk[i  ]);
		ROUND(h, a, b, c, d, e, f, g, k[i+1], blk[i+1]);
		ROUND(g, h, a, b, c, d, e, f, k[i+2], blk[i+2]);
		ROUND(f, g, h, a, b, c, d, e, k[i+3], blk[i+3]);
		ROUND(e, f, g, h, a, b, c, d, k[i+4], blk[i+4]);
		ROUND(d, e, f, g, h, a, b, c, k[i+5], blk[i+5]);
		ROUND(c, d, e, f, g, h, a, b, k[i+6], blk[i+6]);
		ROUND(b, c, d, e, f, g, h, a, k[i+7], blk[i+7]);
	}
	for (i = words; i < 80; i += 8) {
		ROUND2(a, b, c, d, e, f, g, h, k[i  ], i  );
		ROUND2(h, a, b, c, d, e, f, g, k[i+1], i+1);
		ROUND2(g, h, a, b, c, d, e, f, k[i+2], i+2);
		ROUND2(f, g, h, a, b, c, d, e, k[i+3], i+3);
		ROUND2(e, f, g, h, a, b, c, d, k[i+4], i+4);
		ROUND2(d, e, f, g, h, a, b, c, k[i+5], i+5);
		ROUND2(c, d, e, f, g, h, a, b, k[i+6], i+6);
		ROUND2(b, c, d, e, f, g, h, a, k[i+7], i+7);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
