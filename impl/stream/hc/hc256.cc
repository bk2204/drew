#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <drew/plugin.h>
#include <drew/stream.h>
#include "hc256.hh"
#include "stream-plugin.h"
#include "testcase.hh"

extern "C" {

static int hc256_test(void *, const drew_loader_t *);
static int hc256_info(int op, void *p);
static int hc256_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int hc256_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int hc256_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int hc256_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int hc256_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int hc256_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(hc256, hc256_info, hc256_init, hc256_setiv, hc256_setkey, hc256_encrypt, hc256_encrypt, hc256_encrypt, hc256_encrypt, hc256_test, hc256_fini, hc256_clone);

static int hc256_repeated_test(void)
{
	using namespace drew;

	int res = 0;
	uint8_t data[64], keyiv[32];
	uint8_t zero[sizeof(data)];
	const uint8_t ct[64] = {
		0x99, 0xfb, 0xb6, 0xc6, 0x40, 0x14, 0xae, 0xf2,
		0x34, 0xca, 0xd4, 0xa7, 0x4e, 0x69, 0x11, 0x20,
		0xbe, 0xb4, 0x36, 0x6f, 0x5d, 0xb0, 0x0d, 0x42,
		0x90, 0xfd, 0x45, 0x47, 0x95, 0x06, 0x63, 0x7c,
		0xda, 0x7b, 0x1d, 0x5f, 0x36, 0x7e, 0xae, 0x13,
		0x99, 0x53, 0xbc, 0xae, 0x37, 0x7f, 0x3b, 0x73,
		0x66, 0x40, 0xf3, 0x95, 0x1f, 0xd2, 0x01, 0xb6,
		0x30, 0xf8, 0x8c, 0x2d, 0x37, 0x89, 0xc0, 0xa9
	};

	memset(data, 0, sizeof(data));
	memset(keyiv, 0, sizeof(keyiv));
	memset(zero, 0, sizeof(zero));

	HC256 algo;
	algo.SetKey(keyiv, sizeof(keyiv));
	algo.SetNonce(keyiv, sizeof(keyiv));
	for (size_t i = 0; i < 65536; i++)
		algo.Encrypt(data, data, sizeof(data));
	res |= !!memcmp(data, ct, sizeof(data));
	res <<= 1;

	algo.SetKey(keyiv, sizeof(keyiv));
	algo.SetNonce(keyiv, sizeof(keyiv));
	for (size_t i = 0; i < 65536; i++)
		algo.Decrypt(data, data, sizeof(data));
	res |= !!memcmp(data, zero, sizeof(data));

	return res;
}

static int hc256_standard_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<HC256>("00000000000000000000000000000000"
			"00000000000000000000000000000000", 32).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"5b078985d8f6f30d42c5c02fa6b6795153f06534801f89f24e74248b720b4818"
			"cd9227ecebcf4dbf8dbf6977e4ae14fae8504c7bc8a9f3ea6c0106f5327e6981",
			64, "000000000000000000000000000000000"
			"0000000000000000000000000000000", 32);
	res <<= 4;
	res |= StreamTestCase<HC256>("00000000000000000000000000000000"
			"00000000000000000000000000000000", 32).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"afe2a2bf4f17cee9fec2058bd1b18bb15fc042ee712b3101dd501fc60b082a50"
			"06c7feed41923d6348c4daa6ff6185af5a13045e34c44894f3e9e72ddf0b5237",
			64, "010000000000000000000000000000000"
			"0000000000000000000000000000000", 32);
	res <<= 4;
	res |= StreamTestCase<HC256>("55000000000000000000000000000000"
			"00000000000000000000000000000000", 32).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"1c404afe4fe25fed958f9ad1ae36c06f88a65a3cc0abe223aeb3902f420ed3a8"
			"6c3af05944eb396efb79758f5e7a1370d8b7106dcdf7d0adda233472e6dd75f5",
			64, "000000000000000000000000000000000"
			"0000000000000000000000000000000", 32);

	return res;
}

static int hc256_test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	res |= hc256_standard_test();
	res <<= 2;
	res |= hc256_repeated_test();

	return res;
}

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static const int hc256_keysz[] = {32};

static int hc256_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 2;
		case DREW_STREAM_KEYSIZE:
			for (size_t i = 0; i < DIM(hc256_keysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (hc256_keysz[i] > *x)
					return hc256_keysz[i];
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::HC256);
		case DREW_STREAM_BLKSIZE:
			return 4;
		default:
			return -EINVAL;
	}
}

static int hc256_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::HC256 *p;
	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::HC256;
	else
		p = new drew::HC256;
	ctx->ctx = p;
	ctx->functbl = &hc256functbl;
	return 0;
}

static int hc256_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags)
{
	drew::HC256 *p;
	const drew::HC256 *q = reinterpret_cast<drew::HC256 *>(oldctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p = new (newctx->ctx) drew::HC256(*q);
	else
		p = new drew::HC256(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int hc256_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len)
{
	drew::HC256 *p = reinterpret_cast<drew::HC256 *>(ctx->ctx);
	p->SetNonce(key, len);
	return 0;
}

static int hc256_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode)
{
	drew::HC256 *p = reinterpret_cast<drew::HC256 *>(ctx->ctx);
	p->SetKey(key, len);
	return 0;
}

static int hc256_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::HC256 *p = reinterpret_cast<drew::HC256 *>(ctx->ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int hc256_fini(drew_stream_t *ctx, int flags)
{
	drew::HC256 *p = reinterpret_cast<drew::HC256 *>(ctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p->~HC256();
	else 
		delete p;
	return 0;
}

PLUGIN_DATA_START()
PLUGIN_DATA(hc256, "HC256")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

}

drew::HC256::HC256()
{
}


void drew::HC256::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	m_nbytes = 0;
}

void drew::HC256::SetNonce(const uint8_t *iv, size_t sz)
{
	m_ks.SetNonce(iv, sz);
}

void drew::HC256::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXor(out, in, len, m_buf, sizeof(m_buf), m_nbytes, m_ks);
}

void drew::HC256::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::HC256Keystream::endian_t E;

drew::HC256Keystream::HC256Keystream()
{
	Reset();
}

void drew::HC256Keystream::Reset()
{
	ctr = 0;
}

uint32_t drew::HC256Keystream::f1(uint32_t x)
{
	return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}

uint32_t drew::HC256Keystream::f2(uint32_t x)
{
	return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

uint32_t drew::HC256Keystream::g1(uint32_t x, uint32_t y)
{
	return (RotateRight(x, 10) ^ RotateRight(y, 23)) + Q[(x ^ y) % 1024];
}

uint32_t drew::HC256Keystream::g2(uint32_t x, uint32_t y)
{
	return (RotateRight(x, 10) ^ RotateRight(y, 23)) + P[(x ^ y) % 1024];
}

uint32_t drew::HC256Keystream::h1(uint32_t x)
{
	return Q[E::GetByte(x, 0)] + Q[256 + E::GetByte(x, 1)] +
		Q[512 + E::GetByte(x, 2)] + Q[768 + E::GetByte(x, 3)];
}

uint32_t drew::HC256Keystream::h2(uint32_t x)
{
	return P[E::GetByte(x, 0)] + P[256 + E::GetByte(x, 1)] +
		P[512 + E::GetByte(x, 2)] + P[768 + E::GetByte(x, 3)];
}

void drew::HC256Keystream::SetKey(const uint8_t *key, size_t sz)
{
	E::Copy(m_k, key, sz);
}

#define M(i, x) (((i) - (x)) % 1024)
void drew::HC256Keystream::SetNonce(const uint8_t *iv, size_t sz)
{
	uint32_t w[2560];

	memcpy(w, m_k, sizeof(m_k));
	E::Copy(w+8, iv, sz);

	for (size_t i = 16; i < 2560; i++)
		w[i] = f2(w[i-2]) + w[i-7] + f1(w[i-15]) + w[i-16] + i;

	memcpy(P, w+ 512, 1024*sizeof(*w));
	memcpy(Q, w+1536, 1024*sizeof(*w));

	uint8_t dummy[4];
	for (size_t i = 0; i < 4096; i++)
		FillBuffer(dummy);
	ctr = 0;
}

void drew::HC256Keystream::FillBuffer(uint8_t buf[4])
{
	size_t j = ctr % 1024;
	uint32_t s;

	if (!(ctr & 0x400)) {
		P[j] += P[M(j, 10)] + g1(P[M(j, 3)], P[M(j, 1023)]);
		s = h1(P[M(j, 12)]) ^ P[j];
	}
	else {
		Q[j] += Q[M(j, 10)] + g2(Q[M(j, 3)], Q[M(j, 1023)]);
		s = h2(Q[M(j, 12)]) ^ Q[j];
	}
	ctr++;
	E::Copy(buf, &s, sizeof(s));
}
