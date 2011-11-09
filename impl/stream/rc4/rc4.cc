/*-
 * Copyright © 2010–2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <drew/drew.h>
#include <drew/plugin.h>
#include <drew/stream.h>
#include "rc4.hh"
#include "stream-plugin.h"
#include "testcase.hh"

HIDE()
extern "C" {

static int rc4_test(void *, const drew_loader_t *);
static int rc4_info(int op, void *p);
static int rc4_info2(const drew_stream_t *, int op, drew_param_t *,
		const drew_param_t *);
static int rc4_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int rc4_reset(drew_stream_t *ctx);
static int rc4_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int rc4_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int rc4_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int rc4_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int rc4_encryptfast(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int rc4_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(rc4, rc4_info, rc4_info2, rc4_init, rc4_setiv, rc4_setkey, rc4_encrypt, rc4_encrypt, rc4_encryptfast, rc4_encryptfast, rc4_test, rc4_fini, rc4_clone, rc4_reset);

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
			return CURRENT_ABI;
		case DREW_STREAM_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				if (*x < 257)
					return *x + 1;
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::RC4);
		case DREW_STREAM_BLKSIZE:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

static const int rc4keysz[] = {
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32,
	33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 52, 53, 54, 55, 56,
	57, 58, 59, 60, 61, 62, 63, 64,
	65, 66, 67, 68, 69, 70, 71, 72,
	73, 74, 75, 76, 77, 78, 79, 80,
	81, 82, 83, 84, 85, 86, 87, 88,
	89, 90, 91, 92, 93, 94, 95, 96,
	97, 98, 99, 100, 101, 102, 103, 104,
	105, 106, 107, 108, 109, 110, 111, 112,
	113, 114, 115, 116, 117, 118, 119, 120,
	121, 122, 123, 124, 125, 126, 127, 128,
	129, 130, 131, 132, 133, 134, 135, 136,
	137, 138, 139, 140, 141, 142, 143, 144,
	145, 146, 147, 148, 149, 150, 151, 152,
	153, 154, 155, 156, 157, 158, 159, 160,
	161, 162, 163, 164, 165, 166, 167, 168,
	169, 170, 171, 172, 173, 174, 175, 176,
	177, 178, 179, 180, 181, 182, 183, 184,
	185, 186, 187, 188, 189, 190, 191, 192,
	193, 194, 195, 196, 197, 198, 199, 200,
	201, 202, 203, 204, 205, 206, 207, 208,
	209, 210, 211, 212, 213, 214, 215, 216,
	217, 218, 219, 220, 221, 222, 223, 224,
	225, 226, 227, 228, 229, 230, 231, 232,
	233, 234, 235, 236, 237, 238, 239, 240,
	241, 242, 243, 244, 245, 246, 247, 248,
	249, 250, 251, 252, 253, 254, 255, 256
};

static int rc4_info2(const drew_stream_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return CURRENT_ABI;
		case DREW_STREAM_KEYSIZE_LIST:
			for (drew_param_t *p = out; p; p = p->next)
				if (!strcmp(p->name, "keySize")) {
					p->param.array.ptr = (void *)rc4keysz;
					p->param.array.len = DIM(rc4keysz);
				}
			return 0;
		case DREW_STREAM_KEYSIZE_CTX:
			if (ctx && ctx->ctx) {
				const drew::RC4 *algo = (const drew::RC4 *)ctx->ctx;
				return algo->GetKeySize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_STREAM_IVSIZE_LIST:
		case DREW_STREAM_IVSIZE_CTX:
			return -DREW_ERR_NOT_ALLOWED;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::RC4);
		case DREW_STREAM_BLKSIZE:
			return 256;
		default:
			return -DREW_ERR_INVALID;
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
	return -DREW_ERR_NOT_ALLOWED;
}

static int rc4_reset(drew_stream_t *ctx)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx->ctx);
	p->Reset();
	return 0;
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

static int rc4_encryptfast(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::RC4 *p = reinterpret_cast<drew::RC4 *>(ctx->ctx);
	p->EncryptFast(out, in, len);
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
PLUGIN_INTERFACE(rc4)

}

drew::RC4::RC4()
	: m_drop(0)
{
}

drew::RC4::RC4(size_t drop)
	: m_drop(drop)
{
}

void drew::RC4::Reset()
{
	m_ks.Reset();
	m_ks.SetKey(m_key, m_sz);
	for (size_t i = 0; i < m_drop; i++)
		m_ks.GetValue();
	m_nbytes = 0;
	for (size_t i = m_drop & 0xff; i < 256; i++, m_nbytes++)
		m_buf[i] = m_ks.GetValue();
}

void drew::RC4::SetKey(const uint8_t *key, size_t sz)
{
	memcpy(m_key, key, sz);
	m_sz = sz;
	Reset();
}

void drew::RC4::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXor(out, in, len, m_buf, sizeof(m_buf), m_nbytes, m_ks);
}

void drew::RC4::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

void drew::RC4::EncryptFast(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXorAligned(out, in, len, m_buf, sizeof(m_buf), m_ks);
}

void drew::RC4::DecryptFast(uint8_t *out, const uint8_t *in, size_t len)
{
	return EncryptFast(out, in, len);
}
UNHIDE()
