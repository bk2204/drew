/*-
 * Copyright © 2012 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "jh.hh"
#include "testcase.hh"
#include "util.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE2(jh, JH)
PLUGIN_DATA_START()
PLUGIN_DATA(jh, "JH")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(jh)

static int jh_get_digest_size(const drew_param_t *param)
{
	size_t sz = 0;
	for (const drew_param_t *q = param; q; q = q->next)
		if (!strcmp(q->name, "digestSize"))
			sz = q->param.number;
	if (!sz)
		return -DREW_ERR_MORE_INFO;
	if (sz > (512/8) || sz < (224/8))
		return -DREW_ERR_INVALID;
	return sz;
}


static int jhinfo(int op, void *p)
{
	using namespace drew;
	const drew_param_t *param = reinterpret_cast<const drew_param_t *>(p);
	switch (op) {
		case DREW_HASH_VERSION:
			return 3;
		case DREW_HASH_QUANTUM:
			return sizeof(uint64_t);
		case DREW_HASH_SIZE:
			return jh_get_digest_size(param);
		case DREW_HASH_BLKSIZE:
			return 512 / 8;
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE:
			return 1024 / 8;
		case DREW_HASH_INTSIZE:
			return sizeof(JH);
		case DREW_HASH_ENDIAN:
			return BigEndian::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static const int hash_sizes[] = {
	224/8, 256/8, 384/8, 512/8
};

static const int block_sizes[] = {
	512/8
};

static const int buffer_sizes[] = {
	1024/8
};

static int jhinfo2(const drew_hash_t *ctxt, int op, drew_param_t *outp,
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
				const JH *ctx = (const JH *)ctxt->ctx;
				return ctx->GetDigestSize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BLKSIZE_CTX:
			return 512 / 8;
		case DREW_HASH_BUFSIZE_CTX:
			return 1024 / 8;
		case DREW_HASH_INTSIZE:
			return sizeof(JH);
		case DREW_HASH_ENDIAN:
			return BigEndian::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static int jhinit(drew_hash_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param)
{
	using namespace drew;
	int sz = jh_get_digest_size(param);

	if (sz < 0)
		return sz;

	if (flags & DREW_HASH_FIXED)
		ctx->ctx = new (ctx->ctx) JH(sz);
	else
		ctx->ctx = new JH(sz);
	ctx->functbl = &jhfunctbl;
	return 0;
}

static int jhtest(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	typedef VariableSizedHashTestCase<JH, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<JH, 256/8> TestCase256;
	typedef VariableSizedHashTestCase<JH, 384/8> TestCase384;
	typedef VariableSizedHashTestCase<JH, 512/8> TestCase512;

	res |= !TestCase224("", 0).Test("2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630");
	res <<= 1;
	res |= !TestCase224("\xcc", 1).Test("f79c791ac9b9d80ec934312d6b26748481198e3ca78ebb01b2c9ca51");
	res <<= 1;
	res |= !TestCase256("", 0).Test("46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434");
	res <<= 1;
	res |= !TestCase384("", 0).Test("2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328");
	res <<= 1;
	res |= !TestCase512("", 0).Test("90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f");

	return res;
}

}

typedef drew::JH::endian_t E;

drew::JH::JH(size_t sz)
{
	m_size = sz;
	Reset();
}

void drew::JH::Reset()
{
	static const uint8_t zero[64] = {0};
	uint16_t size = m_size << 3;
	
	size = RotateLeft(size, 8);

	memset(m_hash, 0, sizeof(m_hash));
	m_hash[0] = size;
	Transform(m_hash, zero);
	Initialize();
}

inline static void s(uint64_t *buf, uint64_t c)
{
	uint64_t x0 = buf[0], x1 = buf[4], x2 = buf[8], x3 = buf[12];
	uint64_t t;

	x3 = ~x3;
	x0 ^= c & ~x2;
	t = c ^ (x0 & x1);
	x0 ^= x2 & x3;
	x3 ^= (~x1) & x2;
	x1 ^= x0 & x2;
	x2 ^= x0 & (~x3);
	x0 ^= x1 | x3;
	x3 ^= x1 & x2;
	x1 ^= t & x0;
	x2 ^= t;

	buf[ 0] = x0;
	buf[ 4] = x1;
	buf[ 8] = x2;
	buf[12] = x3;
}

inline static void l(uint64_t *buf)
{
	uint64_t b0, b1, b2, b3, b4, b5, b6, b7;

	b4 = buf[ 2] ^ buf[ 4];
	b5 = buf[ 6] ^ buf[ 8];
	b6 = buf[10] ^ buf[12] ^ buf[0];
	b7 = buf[14] ^ buf[ 0];

	b0 = buf[ 0] ^ b5;
	b1 = buf[ 4] ^ b6;
	b2 = buf[ 8] ^ b7 ^ b4;
	b3 = buf[12] ^ b4;

	buf[ 0] = b0;
	buf[ 4] = b1;
	buf[ 8] = b2;
	buf[12] = b3;
	buf[ 2] = b4;
	buf[ 6] = b5;
	buf[10] = b6;
	buf[14] = b7;
}

// Partial round.  Does not include the omega transforms.
inline static void pround(uint64_t *state, const uint64_t *k)
{
	s(state, k[0]);
	s(state+2, k[2]);
	l(state);
	s(state+1, k[1]);
	s(state+3, k[3]);
	l(state+1);
}

inline uint64_t swap1(uint64_t x)
{
	return ((x & 0x5555555555555555ULL) << 1) |
		((x & 0xaaaaaaaaaaaaaaaaULL) >> 1);
}

inline uint64_t swap2(uint64_t x)
{
	return ((x & 0x3333333333333333ULL) << 2) |
		((x & 0xccccccccccccccccULL) >> 2);
}

inline uint64_t swap4(uint64_t x)
{
	return ((x & 0x0f0f0f0f0f0f0f0fULL) << 4) |
		((x & 0xf0f0f0f0f0f0f0f0ULL) >> 4);
}

inline uint64_t swap8(uint64_t x)
{
	return ((x & 0x00ff00ff00ff00ffULL) << 8) |
		((x & 0xff00ff00ff00ff00ULL) >> 8);
}

inline uint64_t swap16(uint64_t x)
{
	return ((x & 0x0000ffff0000ffffULL) << 16) |
		((x & 0xffff0000ffff0000ULL) >> 16);
}

inline uint64_t swap32(uint64_t x)
{
	return (x << 32) | (x >> 32);
}

#define SWAP(f, x) do { \
	x[ 2] = f(x[ 2]); \
	x[ 3] = f(x[ 3]); \
	x[ 6] = f(x[ 6]); \
	x[ 7] = f(x[ 7]); \
	x[10] = f(x[10]); \
	x[11] = f(x[11]); \
	x[14] = f(x[14]); \
	x[15] = f(x[15]); \
} while (0);

#define SWAP64(x) do { \
	std::swap(x[ 2], x[ 3]); \
	std::swap(x[ 6], x[ 7]); \
	std::swap(x[10], x[11]); \
	std::swap(x[14], x[15]); \
} while (0);

static const uint64_t ktbl[] = {
	0x67f815dfa2ded572ULL, 0x571523b70a15847bULL,
	0xf6875a4d90d6ab81ULL, 0x402bd1c3c54f9f4eULL,
	0x9cfa455ce03a98eaULL, 0x9a99b26699d2c503ULL,
	0x8a53bbf2b4960266ULL, 0x31a2db881a1456b5ULL,
	0xdb0e199a5c5aa303ULL, 0x1044c1870ab23f40ULL,
	0x1d959e848019051cULL, 0xdccde75eadeb336fULL,
	0x416bbf029213ba10ULL, 0xd027bbf7156578dcULL,
	0x5078aa3739812c0aULL, 0xd3910041d2bf1a3fULL,
	0x907eccf60d5a2d42ULL, 0xce97c0929c9f62ddULL,
	0xac442bc70ba75c18ULL, 0x23fcc663d665dfd1ULL,
	0x1ab8e09e036c6e97ULL, 0xa8ec6c447e450521ULL,
	0xfa618e5dbb03f1eeULL, 0x97818394b29796fdULL,
	0x2f3003db37858e4aULL, 0x956a9ffb2d8d672aULL,
	0x6c69b8f88173fe8aULL, 0x14427fc04672c78aULL,
	0xc45ec7bd8f15f4c5ULL, 0x80bb118fa76f4475ULL,
	0xbc88e4aeb775de52ULL, 0xf4a3a6981e00b882ULL,
	0x1563a3a9338ff48eULL, 0x89f9b7d524565faaULL,
	0xfde05a7c20edf1b6ULL, 0x362c42065ae9ca36ULL,
	0x3d98fe4e433529ceULL, 0xa74b9a7374f93a53ULL,
	0x86814e6f591ff5d0ULL, 0x9f5ad8af81ad9d0eULL,
	0x6a6234ee670605a7ULL, 0x2717b96ebe280b8bULL,
	0x3f1080c626077447ULL, 0x7b487ec66f7ea0e0ULL,
	0xc0a4f84aa50a550dULL, 0x9ef18e979fe7e391ULL,
	0xd48d605081727686ULL, 0x62b0e5f3415a9e7eULL,
	0x7a205440ec1f9ffcULL, 0x84c9f4ce001ae4e3ULL,
	0xd895fa9df594d74fULL, 0xa554c324117e2e55ULL,
	0x286efebd2872df5bULL, 0xb2c4a50fe27ff578ULL,
	0x2ed349eeef7c8905ULL, 0x7f5928eb85937e44ULL,
	0x4a3124b337695f70ULL, 0x65e4d61df128865eULL,
	0xe720b95104771bc7ULL, 0x8a87d423e843fe74ULL,
	0xf2947692a3e8297dULL, 0xc1d9309b097acbddULL,
	0xe01bdc5bfb301b1dULL, 0xbf829cf24f4924daULL,
	0xffbf70b431bae7a4ULL, 0x48bcf8de0544320dULL,
	0x39d3bb5332fcae3bULL, 0xa08b29e0c1c39f45ULL,
	0x0f09aef7fd05c9e5ULL, 0x34f1904212347094ULL,
	0x95ed44e301b771a2ULL, 0x4a982f4f368e3be9ULL,
	0x15f66ca0631d4088ULL, 0xffaf52874b44c147ULL,
	0x30c60ae2f14abb7eULL, 0xe68c6eccc5b67046ULL,
	0x00ca4fbd56a4d5a4ULL, 0xae183ec84b849ddaULL,
	0xadd1643045ce5773ULL, 0x67255c1468cea6e8ULL,
	0x16e10ecbf28cdaa3ULL, 0x9a99949a5806e933ULL,
	0x7b846fc220b2601fULL, 0x1885d1a07facced1ULL,
	0xd319dd8da15b5932ULL, 0x46b4a5aac01c9a50ULL,
	0xba6b04e467633d9fULL, 0x7eee560bab19caf6ULL,
	0x742128a9ea79b11fULL, 0xee51363b35f7bde9ULL,
	0x76d350755aac571dULL, 0x01707da3fec2463aULL,
	0x42d8a498afc135f7ULL, 0x79676b9e20eced78ULL,
	0xa8db3aea15638341ULL, 0x832c83324d3bc3faULL,
	0xf347271c1f3b40a7ULL, 0x9a762db734f04059ULL,
	0xfd4f21d26c4e3ee7ULL, 0xef5957dc398dfdb8ULL,
	0xdaeb492b490c9b8dULL, 0x0d70f36849d7a25bULL,
	0x84558d7ad0ae3b7dULL, 0x658ef8e4f0e9a5f5ULL,
	0x533b1036f4a2b8a0ULL, 0x5aec3e759e07a80cULL,
	0x4f88e85692946891ULL, 0x4cbcbaf8555cb05bULL,
	0x7b9487f3993bbbe3ULL, 0x5d1c6b72d6f4da75ULL,
	0x6db334dc28acae64ULL, 0x71db28b850a5346cULL,
	0x2a518d10f2e261f8ULL, 0xfc75dd593364dbe3ULL,
	0xa23fce43f1bcac1cULL, 0xb043e8023cd1bb67ULL,
	0x75a12988ca5b0a33ULL, 0x5c5316b44d19347fULL,
	0x1e4d790ec3943b92ULL, 0x3fafeeb6d7757479ULL,
	0x21391abef7d4a8eaULL, 0x5127234c097ef45cULL,
	0xd23c32ba5324a326ULL, 0xadd5a66d4a17a344ULL,
	0x08c9f2afa63e1db5ULL, 0x563c6b91983d5983ULL,
	0x4d608672a17cf84cULL, 0xf6c76e08cc3ee246ULL,
	0x5e76bcb1b333982fULL, 0x2ae6c4efa566d62bULL,
	0x36d4c1bee8b6f406ULL, 0x6321efbc1582ee74ULL,
	0x69c953f40d4ec1fdULL, 0x26585806c45a7da7ULL,
	0x16fae0061614c17eULL, 0x3f9d63283daf907eULL,
	0x0cd29b00e3f2c9d2ULL, 0x300cd4b730ceaa5fULL,
	0x9832e0f216512a74ULL, 0x9af8cee3d830eb0dULL,
	0x9279f1b57b9ec54bULL, 0xd36886046ee651ffULL,
	0x316796e6574d239bULL, 0x05750a17f3a6e6ccULL,
	0xce6c3213d98176b1ULL, 0x62a205f88452173cULL,
	0x47154778b3cb2bf4ULL, 0x486a9323825446ffULL,
	0x65655e4e0758df38ULL, 0x8e5086fc897cfcf2ULL,
	0x86ca0bd0442e7031ULL, 0x4e477830a20940f0ULL,
	0x8338f7d139eea065ULL, 0xbd3a2ce437e95ef7ULL,
	0x6ff8130126b29721ULL, 0xe7de9fefd1ed44a3ULL,
	0xd992257615dfa08bULL, 0xbe42dc12f6f7853cULL,
	0x7eb027ab7ceca7d8ULL, 0xdea83eaada7d8d53ULL,
	0xd86902bd93ce25aaULL, 0xf908731afd43f65aULL,
	0xa5194a17daef5fc0ULL, 0x6a21fd4c33664d97ULL,
	0x701541db3198b435ULL, 0x9b54cdedbb0f1eeaULL,
	0x72409751a163d09aULL, 0xe26f4791bf9d75f6ULL,
};

void drew::JH::Transform(uint64_t *state, const uint8_t *block)
{
	const uint64_t *k = ktbl;
	uint64_t blk[8] = {0};
	const uint64_t *p = LittleEndian::CopyIfNeeded(blk, block, sizeof(blk));

	XorBuffers(state, p, sizeof(blk));
	for (size_t i = 0; i < 42; i += 7, k += 28) {
		pround(state, k);
		SWAP(swap1, state);
		pround(state, k+ 4);
		SWAP(swap2, state);
		pround(state, k+ 8);
		SWAP(swap4, state);
		pround(state, k+12);
		SWAP(swap8, state);
		pround(state, k+16);
		SWAP(swap16, state);
		pround(state, k+20);
		SWAP(swap32, state);
		pround(state, k+24);
		SWAP64(state);
	}
	XorBuffers(state+8, p, sizeof(blk));
}

void drew::JH::Pad()
{
	uint64_t len[2];

	const size_t lenoff = m_len[0];
	const size_t trip = block_size - sizeof(len);
	const bool is_big =
		NativeEndian::GetEndianness() == BigEndian::GetEndianness();
	const size_t noff = lenoff % block_size;
	size_t off = noff + 1;
	const ssize_t modval = (-lenoff) % 64;
	size_t totalpad = 48 - 1 + (modval < 0 ? modval + 64 : modval);
	uint8_t *buf = m_buf;
	/* Convert bytes to bits. */
	len[!is_big] = (m_len[1]<<3)|(m_len[0]>>((sizeof(m_len[0])*8)-3));
	len[is_big] = m_len[0]<<3;
	
	/* There is always at least one byte free. */
	buf[noff] = 0x80;
	while (totalpad) {
		size_t npadded = std::min(totalpad, block_size-off);
		memset(buf+off, 0, npadded);
		off += npadded;
		if (off == block_size) {
			off = 0;
			Transform(buf);
		}
		totalpad -= npadded;
	}
	memset(buf+off, 0, trip-off);
	BigEndian::Copy(buf+trip, len, sizeof(len), sizeof(len));
	Transform(buf);
}

void drew::JH::GetDigest(uint8_t *digest, size_t len, bool nopad)
{
	uint8_t buf[1024/8];
	const size_t offset = sizeof(m_hash) - m_size;

	if (!nopad)
		Pad();
	
	E::Copy(buf, m_hash, sizeof(buf));
	memcpy(digest, buf+offset, std::min(m_size, len));
	memset(buf, 0, sizeof(buf));
}
