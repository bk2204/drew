#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "sha256.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(sha256, drew::SHA256)
PLUGIN_STRUCTURE(sha224, drew::SHA224)
PLUGIN_DATA_START()
PLUGIN_DATA(sha256, "SHA-256")
PLUGIN_DATA(sha224, "SHA-224")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

static int sha256test(void *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<SHA256>("", 0).Test("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	res <<= 1;
	res |= !HashTestCase<SHA256>("a", 1).Test("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
	res <<= 1;
	res |= !HashTestCase<SHA256>("abc", 1).Test("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	res <<= 1;
	res |= !HashTestCase<SHA256>("message digest", 1).Test("f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
	res <<= 1;
	res |= !HashTestCase<SHA256>("abcdefghijklmnopqrstuvwxyz", 1).Test("71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
	res <<= 1;
	res |= !HashTestCase<SHA256>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0");
	res <<= 1;
	res |= !HashTestCase<SHA256>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e");
	res <<= 1;
	res |= !HashTestCase<SHA256>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	res <<= 1;
	res |= !HashTestCase<SHA256>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

	return res;
}

static int sha224test(void *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<SHA224>("", 0).Test("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
	res <<= 1;
	res |= !HashTestCase<SHA224>("a", 1).Test("abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5");
	res <<= 1;
	res |= !HashTestCase<SHA224>("abc", 1).Test("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
	res <<= 1;
	res |= !HashTestCase<SHA224>("message digest", 1).Test("2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb");
	res <<= 1;
	res |= !HashTestCase<SHA224>("abcdefghijklmnopqrstuvwxyz", 1).Test("45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2");
	res <<= 1;
	res |= !HashTestCase<SHA224>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9");
	res <<= 1;
	res |= !HashTestCase<SHA224>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e");
	res <<= 1;
	res |= !HashTestCase<SHA224>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
	res <<= 1;
	res |= !HashTestCase<SHA224>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");

	return res;
}
}

/* 32-bit rotate-right. */
static inline uint32_t ROR(uint32_t x, int n)
{
	return ((x>>n)|(x<<(32-n)));
}

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (z^(x&(y^z)));
}
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y)^(x&z)^(y&z);
}
static inline uint32_t S0(uint32_t x)
{
	return ROR(x, 2)^ROR(x, 13)^ROR(x, 22);
}
static inline uint32_t S1(uint32_t x)
{
	return ROR(x, 6)^ROR(x, 11)^ROR(x, 25);
}
static inline uint32_t s0(uint32_t x)
{
	return ROR(x, 7)^ROR(x, 18)^(x>>3);
}
static inline uint32_t s1(uint32_t x)
{
	return ROR(x, 17)^ROR(x, 19)^(x>>10);
}

static const uint32_t k[]={
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROUND(a, b, c, d, e, f, g, h, k, blk) \
	h+=S1(e)+Ch(e, f, g)+k+blk; \
	d+=h; \
	h+=S0(a)+Maj(a, b, c)

#define ROUND2(a, b, c, d, e, f, g, h, k, i) \
	blk[i] = s1(blk[i-2]) + blk[i-7] + s0(blk[i-15]) + blk[i-16]; \
	ROUND(a, b, c, d, e, f, g, h, k, blk[i]); 

drew::SHA256::SHA256()
{
	m_hash[0] = 0x6a09e667;
	m_hash[1] = 0xbb67ae85;
	m_hash[2] = 0x3c6ef372;
	m_hash[3] = 0xa54ff53a;
	m_hash[4] = 0x510e527f;
	m_hash[5] = 0x9b05688c;
	m_hash[6] = 0x1f83d9ab;
	m_hash[7] = 0x5be0cd19;
	Initialize();
}

drew::SHA224::SHA224()
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

void drew::SHA256Transform::Transform(uint32_t *state, const uint8_t *block)
{
	// This is normally defined automatically by Hash.
	const size_t block_size = 64;
	const size_t words = block_size / sizeof(uint32_t);
	uint32_t blk[64];
	size_t i;
	uint32_t a, b, c, d, e, f, g, h;

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
	for (i = words; i < 64; i += 8) {
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
