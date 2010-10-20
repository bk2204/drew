#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <plugin.h>
#include <stream.h>
#include "rc4.hh"
#include "stream-plugin.h"
#include "testcase.hh"

extern "C" {

static int rc4_test(void *, drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<RC4>("57696b69").Test("7065646961", "1021bf0420");
	res <<= 2;
	res |= StreamTestCase<RC4>("4b6579").Test("506c61696e74657874",
			"bbf316e8d940af0ad3");
	res <<= 2;
	res |= StreamTestCase<RC4>("536563726574").Test("41747461636b206174206461776e",
			"45a01f645fc35b383552544b9bf5");

	return res;
}

static int rc4_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 1;
		case DREW_STREAM_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				if (*x < 257)
					return *x + 1;
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::RC4);
		default:
			return -EINVAL;
	}
}

static int rc4_init(void **ctx, void *data, int flags, drew_loader_t *, const drew_param_t *)
{
	drew::RC4 *p = new drew::RC4;
	if (flags & DREW_STREAM_INIT_FIXED) {
		memcpy(*ctx, p, sizeof(*p));
		delete p;
	}
	else
		*ctx = p;
	return 0;
}

static int rc4_clone(void **newctx, void *oldctx, int flags)
{
	drew::RC4 *p = new drew::RC4(*reinterpret_cast<drew::RC4 *>(oldctx));
	if (flags & DREW_STREAM_CLONE_FIXED) {
		memcpy(*newctx, p, sizeof(*p));
		delete p;
	}
	else
		*newctx = p;
	return 0;
}

static int rc4_setiv(void *ctx, const uint8_t *key, size_t len)
{
	return -EINVAL;
}

static int rc4_setkey(void *ctx, const uint8_t *key, size_t len, int mode)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx);
	p->SetKey(key, len);
	return 0;
}

static int rc4_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int rc4_decrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	return rc4_encrypt(ctx, out, in, len);
}

static int rc4_fini(void **ctx, int flags)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(*ctx);
	if (flags & DREW_STREAM_FINI_NO_DEALLOC)
		p->~RC4();
	else {
		delete p;
		*ctx = NULL;
	}
	return 0;
}

PLUGIN_FUNCTBL(rc4, rc4_info, rc4_init, rc4_setiv, rc4_setkey, rc4_encrypt, rc4_decrypt, rc4_test, rc4_fini, rc4_clone);
PLUGIN_DATA_START()
PLUGIN_DATA(rc4, "RC4")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

}

drew::RC4::RC4()
	: m_drop(0)
{
}

drew::RC4::RC4(size_t drop)
	: m_drop(drop)
{
}

void drew::RC4::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	for (size_t i = 0; i < m_drop; i++)
		m_ks.GetValue();
}

void drew::RC4::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	for (size_t i = 0; i < len; i++)
		*out++ = *in++ ^ m_ks.GetValue();
}

void drew::RC4::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

drew::RC4Keystream::RC4Keystream()
{
	Reset();
}

void drew::RC4Keystream::SetKey(const uint8_t *key, size_t sz)
{
	obj_t j = 0;
	for (size_t i = 0; i < 256; i++) {
		j += s[i] + key[i % sz];
		std::swap(s[i], s[uint8_t(j)]);
	}
}

void drew::RC4Keystream::Reset()
{
	for (size_t i = 0; i < 256; i++)
		s[i] = i;
	this->i = 0;
	this->j = 0;
}

drew::RC4Keystream::obj_t drew::RC4Keystream::GetValue()
{
	i++;
	obj_t &x = s[uint8_t(i)];
	j += x;
	obj_t &y = s[uint8_t(j)];
	std::swap(x, y);
	return s[uint8_t(x + y)];
}
