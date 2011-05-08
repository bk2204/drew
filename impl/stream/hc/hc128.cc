#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <drew/plugin.h>
#include <drew/stream.h>
#include "hc128.hh"
#include "stream-plugin.h"
#include "testcase.hh"

extern "C" {

static int hc128_test(void *, const drew_loader_t *);
static int hc128_info(int op, void *p);
static int hc128_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int hc128_reset(drew_stream_t *ctx);
static int hc128_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int hc128_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int hc128_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int hc128_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int hc128_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(hc128, hc128_info, hc128_init, hc128_setiv, hc128_setkey, hc128_encrypt, hc128_encrypt, hc128_encrypt, hc128_encrypt, hc128_test, hc128_fini, hc128_clone, hc128_reset);

static int hc128_repeated_test(void)
{
	using namespace drew;

	int res = 0;
	uint8_t data[64], keyiv[16];
	uint8_t zero[sizeof(data)];
	const uint8_t ct[64] = {
		0x26, 0xc0, 0xea, 0xa4, 0x26, 0x11, 0x49, 0x7e,
		0x4f, 0x38, 0x2a, 0x6a, 0x29, 0x13, 0x4e, 0x5c,
		0xa1, 0x7f, 0x40, 0xda, 0xae, 0xb1, 0xe6, 0x55,
		0xf3, 0xfd, 0xc6, 0x05, 0x86, 0x8a, 0xdc, 0xbb,
		0xa0, 0x9a, 0x69, 0x7a, 0x17, 0xc1, 0x4d, 0x1a,
		0xcc, 0x8c, 0x65, 0x63, 0x74, 0x24, 0xe6, 0xd3,
		0x6f, 0x23, 0xf8, 0x9c, 0x21, 0xbe, 0x31, 0x01,
		0xe9, 0x1d, 0xa5, 0xc3, 0xde, 0x90, 0x22, 0xd1
	};

	memset(data, 0, sizeof(data));
	memset(keyiv, 0, sizeof(keyiv));
	memset(zero, 0, sizeof(zero));

	HC128 algo;
	algo.SetKey(keyiv, sizeof(keyiv));
	algo.SetNonce(keyiv, sizeof(keyiv));
	for (size_t i = 0; i < 1048576; i++)
		algo.Encrypt(data, data, sizeof(data));
	res |= !!memcmp(data, ct, sizeof(data));
	res <<= 1;

	algo.SetKey(keyiv, sizeof(keyiv));
	algo.SetNonce(keyiv, sizeof(keyiv));
	for (size_t i = 0; i < 1048576; i++)
		algo.Decrypt(data, data, sizeof(data));
	res |= !!memcmp(data, zero, sizeof(data));

	return res;
}

static int hc128_standard_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<HC128>("00000000000000000000000000000000", 16).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"82001573a003fd3b7fd72ffb0eaf63aac62f12deb629dca72785a66268ec758b"
			"1edb36900560898178e0ad009abf1f491330dc1c246e3d6cb264f6900271d59c",
			64, "00000000000000000000000000000000", 16);
	res <<= 4;
	res |= StreamTestCase<HC128>("00000000000000000000000000000000", 16).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"d59318c058e9dbb798ec658f046617642467fc36ec6e2cc8a7381c1b952ab4c9"
			"23f13e328b906a0a687b75cebbf7149f11e0cde43f17b5ae948c6089ca46cfb5",
			64, "01000000000000000000000000000000", 16);
	res <<= 4;
	res |= StreamTestCase<HC128>("55000000000000000000000000000000", 16).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"a45182510a93b40431f92ab032f039067aa4b4bc0b482257729ff92b66e5c0cd"
			"560c0f31e883ccd3efb83d667fe0df6290173e599caacec56f8003aba0e5a6c9",
			64, "00000000000000000000000000000000", 16);

	return res;
}

static int hc128_test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	res |= hc128_standard_test();
	res <<= 2;
	res |= hc128_repeated_test();

	return res;
}

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static const int hc128_keysz[] = {16};

static int hc128_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 2;
		case DREW_STREAM_KEYSIZE:
			for (size_t i = 0; i < DIM(hc128_keysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (hc128_keysz[i] > *x)
					return hc128_keysz[i];
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::HC128);
		case DREW_STREAM_BLKSIZE:
			return 4;
		default:
			return -EINVAL;
	}
}

static int hc128_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::HC128 *p;
	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::HC128;
	else
		p = new drew::HC128;
	ctx->ctx = p;
	ctx->functbl = &hc128functbl;
	return 0;
}

static int hc128_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags)
{
	drew::HC128 *p;
	const drew::HC128 *q = reinterpret_cast<drew::HC128 *>(oldctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p = new (newctx->ctx) drew::HC128(*q);
	else
		p = new drew::HC128(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int hc128_reset(drew_stream_t *ctx)
{
	drew::HC128 *p = reinterpret_cast<drew::HC128 *>(ctx->ctx);
	p->Reset();
	return 0;
}

static int hc128_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len)
{
	drew::HC128 *p = reinterpret_cast<drew::HC128 *>(ctx->ctx);
	p->SetNonce(key, len);
	return 0;
}

static int hc128_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode)
{
	drew::HC128 *p = reinterpret_cast<drew::HC128 *>(ctx->ctx);
	p->SetKey(key, len);
	return 0;
}

static int hc128_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::HC128 *p = reinterpret_cast<drew::HC128 *>(ctx->ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int hc128_fini(drew_stream_t *ctx, int flags)
{
	drew::HC128 *p = reinterpret_cast<drew::HC128 *>(ctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p->~HC128();
	else 
		delete p;
	return 0;
}

PLUGIN_DATA_START()
PLUGIN_DATA(hc128, "HC128")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

}

drew::HC128::HC128()
{
}


void drew::HC128::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	m_nbytes = 0;
}

void drew::HC128::Reset()
{
	m_ks.Reset();
	m_ks.SetNonce(m_iv, 16);
	m_nbytes = 0;
}

void drew::HC128::SetNonce(const uint8_t *iv, size_t sz)
{
	memcpy(m_iv, iv, sz);
	m_ks.SetNonce(iv, sz);
}

void drew::HC128::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXor(out, in, len, m_buf, sizeof(m_buf), m_nbytes, m_ks);
}

void drew::HC128::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::HC128Keystream::endian_t E;

drew::HC128Keystream::HC128Keystream()
{
	Reset();
}

void drew::HC128Keystream::Reset()
{
	ctr = 0;
}

uint32_t drew::HC128Keystream::f1(uint32_t x)
{
	return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}

uint32_t drew::HC128Keystream::f2(uint32_t x)
{
	return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

uint32_t drew::HC128Keystream::g1(uint32_t x, uint32_t y, uint32_t z)
{
	return (RotateRight(x, 10) ^ RotateRight(z, 23)) + RotateRight(y, 8);
}

uint32_t drew::HC128Keystream::g2(uint32_t x, uint32_t y, uint32_t z)
{
	return (RotateLeft(x, 10) ^ RotateLeft(z, 23)) + RotateLeft(y, 8);
}

uint32_t drew::HC128Keystream::h1(uint32_t x)
{
	return Q[E::GetByte(x, 0)] + Q[256 + E::GetByte(x, 2)];
}

uint32_t drew::HC128Keystream::h2(uint32_t x)
{
	return P[E::GetByte(x, 0)] + P[256 + E::GetByte(x, 2)];
}

void drew::HC128Keystream::SetKey(const uint8_t *key, size_t sz)
{
	E::Copy(m_k, key, sz);
}

#define M(i, x) (((i) - (x)) % 512)
void drew::HC128Keystream::SetNonce(const uint8_t *iv, size_t sz)
{
	uint32_t w[1280];

	memcpy(w, m_k, sizeof(m_k));
	memcpy(w+4, m_k, sizeof(m_k));
	E::Copy(w+8, iv, sz);
	memcpy(w+12, w+8, sz);

	for (size_t i = 16; i < 1280; i++)
		w[i] = f2(w[i-2]) + w[i-7] + f1(w[i-15]) + w[i-16] + i;

	memcpy(P, w+256, 512*sizeof(*w));
	memcpy(Q, w+768, 512*sizeof(*w));

	for (size_t i = 0; i < 512; i++) {
		P[i] = (P[i] + g1(P[M(i, 3)], P[M(i, 10)], P[M(i, 511)])) ^
				h1(P[M(i, 12)]);
	}
	for (size_t i = 0; i < 512; i++) {
		Q[i] = (Q[i] + g2(Q[M(i, 3)], Q[M(i, 10)], Q[M(i, 511)])) ^
				h2(Q[M(i, 12)]);
	}
}

void drew::HC128Keystream::FillBuffer(uint8_t buf[4])
{
	size_t j = ctr % 512;
	uint32_t s;

	if (!(ctr & 0x200)) {
		P[j] += g1(P[M(j, 3)], P[M(j, 10)], P[M(j, 511)]);
		s = h1(P[M(j, 12)]) ^ P[j];
	}
	else {
		Q[j] += g2(Q[M(j, 3)], Q[M(j, 10)], Q[M(j, 511)]);
		s = h2(Q[M(j, 12)]) ^ Q[j];
	}
	ctr++;
	E::Copy(buf, &s, sizeof(s));
}
