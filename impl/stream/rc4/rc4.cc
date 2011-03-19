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

static int rc4_test(void *, const drew_loader_t *);
static int rc4_info(int op, void *p);
static int rc4_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int rc4_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int rc4_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int rc4_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int rc4_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int rc4_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(rc4, rc4_info, rc4_init, rc4_setiv, rc4_setkey, rc4_encrypt, rc4_encrypt, rc4_encrypt, rc4_encrypt, rc4_test, rc4_fini, rc4_clone);

static int rc4_maintenance_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<RC4>::MaintenanceTest("2ac8ce81c12248c868ecddfb28b117eef"
			"6f79d57a9fdc573183e9cd860df2ce40530135a6aa98a101140529b2092683e8e3fc2"
			"ab16cf291443603aaf78ba8bf42f19630893cdc9358c85aafaef01fdd222e131fce20"
			"7e76eecb5d555326fc01faa1fa56fa6d992278864dc84ac3807fa520ea1373f7b892e"
			"aabe521e62e9d754", 16);
	res |= StreamTestCase<RC4>::MaintenanceTest("50b145c20f5aceba1fa7ecb56e1a17f7c"
			"38994258a6c06c11698c3f7122fc4576fb09125d066908c5e0066b0ef339427845ed4"
			"ad485e10941fa983723abea6d6d1303174145393aaa6da902465c82c5957687a4362f"
			"abbf70900314b437f4b2528916cb219531b11894086b1635173d6fa33dd19c3ae2a7f"
			"1fa236ff5e2b9138", 20);
	res |= StreamTestCase<RC4>::MaintenanceTest("6fb291ae1d92ae63d5c664a25899888d9"
			"6b34112f97721478e895d10ccc75eaef3ce4697469be3c5f5e999b8f4efa0a6765d4a"
			"c02e7eb220d7fb5f96879ec45337a39e794b15f24134fb963484c23fb9cea87a2c29f"
			"952e7e7a6d33b4803f6d011e9a1e88a2aa2ba91e3c40139e533eb506e9ccf6747191e"
			"04a44811f8d47bcd", 24);
	res |= StreamTestCase<RC4>::MaintenanceTest("90d24e2d721b1c390e02e631553ceab99"
			"b03b90b5c37247d0ad09f1f0621c40a6cd1d3847f82e48baa561bd331f25717b77da6"
			"9f159d1e8586f4c218b349afc84f7ada14f2d7c179ea4e65f0547077cf46ec000a5b7"
			"12907c07868048e404cbc8a3b46a37b02626a9cd523ad774339ba8c243009208003ac"
			"ff1526835f59ff22", 28);
	res |= StreamTestCase<RC4>::MaintenanceTest("ee549d7867217e4db9d85b1eddf18f7fc"
			"a633868c1fc4227cb49472032f2c8f3545e273b502da032d240665cdc2b321fc5059f"
			"263e672cd819c461fe009239554eff6d2397d3a976d452c1efab7c57745f98af6dcbc"
			"bc35fa8bdd8b171e25a84441517d6ad98b4b88d5945ecb3878bcd9ca2a06895181f13"
			"9b1d639b943fc8b6", 32);

	return res;
}

static int rc4_test(void *, const drew_loader_t *)
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
	res <<= 2;
	res |= rc4_maintenance_test();

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

static int rc4_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::RC4 *p;
	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::RC4;
	else
		p = new drew::RC4;
	ctx->ctx = p;
	ctx->functbl = &rc4functbl;
	return 0;
}

static int rc4_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags)
{
	drew::RC4 *p;
	const drew::RC4 *q = reinterpret_cast<drew::RC4 *>(oldctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p = new (newctx->ctx) drew::RC4(*q);
	else
		p = new drew::RC4(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int rc4_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len)
{
	return -EINVAL;
}

static int rc4_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx->ctx);
	p->SetKey(key, len);
	return 0;
}

static int rc4_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx->ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int rc4_fini(drew_stream_t *ctx, int flags)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p->~RC4();
	else
		delete p;
	return 0;
}

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
