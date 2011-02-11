#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <plugin.h>
#include <stream.h>
#include "rabbit.hh"
#include "stream-plugin.h"
#include "testcase.hh"

extern "C" {

static int rabbit_test(void *, drew_loader_t *)
{
	using namespace drew;

	const char *allzeros = "000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000";
	const char *key1 = "acc351dcf162fc3bfe363d2e29132891";
	const char *key2 = "43009bc001abe9e933c7e08715749583";

	int res = 0;

	res |= StreamTestCase<Rabbit>(allzeros, 16).Test(allzeros,
			"02f74a1c26456bf5ecd6a536f05457b1"
			"a78ac689476c697b390c9cc515d8e888"
			"96d6731688d168da51d40c70c3a116f4");
	res <<= 1;
	res |= StreamTestCase<Rabbit>(key1, 16).Test(allzeros,
			"9c51e28784c37fe9a127f63ec8f32d3d"
			"19fc5485aa53bf96885b40f461cd76f5"
			"5e4c4d20203be58a5043dbfb737454e5");
	res <<= 1;
	res |= StreamTestCase<Rabbit>(key2, 16).Test(allzeros,
			"9b60d002fd5ceb32accd41a0cd0db10c"
			"ad3eff4c1192707b5a01170fca9ffc95"
			"2874943aad4741923f7ffc8bdee54996");
	res <<= 1;
	res |= StreamTestCase<Rabbit>(allzeros, 16).Test(allzeros,
			"edb70567375dcd7cd89554f85e27a7c6"
			"8d4adc7032298f7bd4eff504aca6295f"
			"668fbf478adb2be51e6cde292b82de2a",
			48, allzeros, 8);
	res <<= 1;
	res |= StreamTestCase<Rabbit>(allzeros, 16).Test(allzeros,
			"6d7d012292ccdce0e2120058b94ecd1f"
			"2e6f93edff99247b012521d1104e5fa7"
			"a79b0212d0bd56233938e793c312c1eb",
			48, "597e26c175f573c3", 8);
	res <<= 1;
	res |= StreamTestCase<Rabbit>(allzeros, 16).Test(allzeros,
			"4d1051a123afb670bf8d8505c8d85a44"
			"035bc3acc667aeae5b2cf44779f2c896"
			"cb5115f034f03d31171ca75f89fccb9f",
			48, "2717f4d21a56eba6", 8);

	return res;
}

static int rabbit_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 1;
		case DREW_STREAM_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				return *x ? 0 : 16;
			}
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::Rabbit);
		default:
			return -EINVAL;
	}
}

static int rabbit_init(void **ctx, void *data, int flags, drew_loader_t *, const drew_param_t *)
{
	drew::Rabbit *p = new drew::Rabbit;
	if (flags & DREW_STREAM_INIT_FIXED) {
		memcpy(*ctx, p, sizeof(*p));
		delete p;
	}
	else
		*ctx = p;
	return 0;
}

static int rabbit_clone(void **newctx, void *oldctx, int flags)
{
	drew::Rabbit *p = new drew::Rabbit(*reinterpret_cast<drew::Rabbit *>(oldctx));
	if (flags & DREW_STREAM_CLONE_FIXED) {
		memcpy(*newctx, p, sizeof(*p));
		delete p;
	}
	else
		*newctx = p;
	return 0;
}

static int rabbit_setiv(void *ctx, const uint8_t *key, size_t len)
{
	drew::Rabbit *p = reinterpret_cast<drew::Rabbit *>(ctx);
	p->SetNonce(key, len);
	return 0;
}

static int rabbit_setkey(void *ctx, const uint8_t *key, size_t len, int mode)
{
	drew::Rabbit *p = reinterpret_cast<drew::Rabbit *>(ctx);
	p->SetKey(key, len);
	return 0;
}

static int rabbit_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	drew::Rabbit *p = reinterpret_cast<drew::Rabbit *>(ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int rabbit_fini(void **ctx, int flags)
{
	drew::Rabbit *p = reinterpret_cast<drew::Rabbit *>(*ctx);
	if (flags & DREW_STREAM_FINI_NO_DEALLOC)
		p->~Rabbit();
	else {
		delete p;
		*ctx = NULL;
	}
	return 0;
}

PLUGIN_FUNCTBL(rabbit, rabbit_info, rabbit_init, rabbit_setiv, rabbit_setkey, rabbit_encrypt, rabbit_encrypt, rabbit_test, rabbit_fini, rabbit_clone);
PLUGIN_DATA_START()
PLUGIN_DATA(rabbit, "Rabbit")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

}

drew::Rabbit::Rabbit()
{
}

void drew::Rabbit::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	m_nbytes = 0;
}

void drew::Rabbit::SetNonce(const uint8_t *nonce, size_t sz)
{
	m_ks.SetNonce(nonce, sz);
}

void drew::Rabbit::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	const uint8_t *buf = m_buf + (sizeof(m_buf) - m_nbytes);
	while (m_nbytes-- && len--)
		*out++ = *in++ ^ *buf++;
	while (len) {
		m_ks.GetValue(m_buf);
		m_nbytes = sizeof(m_buf);
		buf = m_buf;
		while (m_nbytes-- && len--)
			*out++ = *in++ ^ *buf++;
	}
	if (m_nbytes > sizeof(m_buf))
		m_nbytes = 0;
}

void drew::Rabbit::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::RabbitKeystream::endian_t E;

drew::RabbitKeystream::RabbitKeystream()
{
	Reset();
}

void drew::RabbitKeystream::CounterUpdate()
{
	static const uint64_t a[8] = {
		0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d,
		0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3
	};
	// Really, all we need b to do here is reflect the carry bit for the
	// addition.  There is probably a simpler yet equally portable way to do
	// this.
	for (size_t i = 0; i < 8; i++) {
		uint64_t temp = c[i] + a[i] + b;
		b = (temp & 0xffffffff00000000);
		c[i] = uint32_t(temp);
	}
}

inline uint64_t drew::RabbitKeystream::square(uint32_t term)
{
	return uint64_t(term) * term;
}

inline uint32_t drew::RabbitKeystream::g(uint32_t u, uint32_t v)
{
	uint64_t res = square(u+v);
	return (res >> 32) ^ uint32_t(res);
}

void drew::RabbitKeystream::NextState()
{
	uint32_t g[8];
	for (size_t i = 0; i < 8; i++)
		g[i] = this->g(x[i], c[i]);
	x[0] = g[0] + RotateLeft(g[7], 16) + RotateLeft(g[6], 16);
	x[1] = g[1] + RotateLeft(g[0],  8) + g[7];
	x[2] = g[2] + RotateLeft(g[1], 16) + RotateLeft(g[0], 16);
	x[3] = g[3] + RotateLeft(g[2],  8) + g[1];
	x[4] = g[4] + RotateLeft(g[3], 16) + RotateLeft(g[2], 16);
	x[5] = g[5] + RotateLeft(g[4],  8) + g[3];
	x[6] = g[6] + RotateLeft(g[5], 16) + RotateLeft(g[4], 16);
	x[7] = g[7] + RotateLeft(g[6],  8) + g[5];
}

void drew::RabbitKeystream::SetKey(const uint8_t *key, size_t sz)
{
	uint16_t kbuf[8];
	const uint16_t *k;
	k = E::CopyIfNeeded(kbuf, key, sizeof(kbuf));
	for (size_t i = 0; i < 8; i += 2) {
		x[i+0] = (uint32_t(k[(i+1)&7]) << 16) | k[i];
		c[i+0] = (uint32_t(k[(i+4)&7]) << 16) | k[(i+5)&7];
		x[i+1] = (uint32_t(k[(i+6)&7]) << 16) | k[(i+5)&7];
		c[i+1] = (uint32_t(k[(i+1)&7]) << 16) | k[(i+2)&7];
	}
	for (size_t i = 0; i < 4; i++) {
		CounterUpdate();
		NextState();
	}
	for (size_t i = 0; i < 8; i++)
		c[i] ^= x[(i+4)&7];
}

void drew::RabbitKeystream::SetNonce(const uint8_t *ivin, size_t sz)
{
	uint32_t ivbuf[2];
	const uint32_t *iv;
	iv = E::CopyIfNeeded(ivbuf, ivin, sizeof(ivbuf));

	c[0] ^= iv[0];
	c[1] ^= (iv[1] & 0xffff0000) | (iv[0] >> 16);
	c[2] ^= iv[1];
	c[3] ^= (iv[1] << 16) | uint16_t(iv[0]);
	c[4] ^= iv[0];
	c[5] ^= (iv[1] & 0xffff0000) | (iv[0] >> 16);
	c[6] ^= iv[1];
	c[7] ^= (iv[1] << 16) | uint16_t(iv[0]);

	for (size_t i = 0; i < 4; i++) {
		CounterUpdate();
		NextState();
	}
}

void drew::RabbitKeystream::Reset()
{
	this->b = 0;
}

void drew::RabbitKeystream::GetValue(uint32_t s[4])
{
	CounterUpdate();
	NextState();

	s[0] = x[0] ^ (x[5] >> 16) ^ (x[3] << 16);
	s[1] = x[2] ^ (x[7] >> 16) ^ (x[5] << 16);
	s[2] = x[4] ^ (x[1] >> 16) ^ (x[7] << 16);
	s[3] = x[6] ^ (x[3] >> 16) ^ (x[1] << 16);
}

void drew::RabbitKeystream::GetValue(uint8_t buf[16])
{
	uint32_t s[4];
	GetValue(s);
	E::Copy(buf, s, sizeof(s));
}
