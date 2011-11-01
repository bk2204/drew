/*-
 * Copyright © 2011 brian m. carlson
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

#include <internal.h>

#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.hh"
#include "shacal.hh"
#include "sha1/sha1.hh"
#include "sha256/sha256.hh"
#include "btestcase.hh"

HIDE()
extern "C" {
	PLUGIN_STRUCTURE2(shacal1, SHACAL1)
	PLUGIN_STRUCTURE2(shacal2, SHACAL2)
	PLUGIN_DATA_START()
	PLUGIN_DATA(shacal1, "SHACAL-1")
	PLUGIN_DATA(shacal2, "SHACAL-2")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(shacal)

static int shacalkeysz[] = {
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
	121, 122, 123, 124, 125, 126, 127, 128
};

static int shacal1info(int op, void *p)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return CURRENT_ABI;
		case DREW_BLOCK_BLKSIZE:
			return 20;
		case DREW_BLOCK_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				if (*x < 512/8)
					return *x + 1;
			}
			return 0;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::SHACAL1);
		case DREW_BLOCK_ENDIAN:
			return drew::SHACAL1::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static int shacal1info2(const drew_block_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return CURRENT_ABI;
		case DREW_BLOCK_BLKSIZE:
			return 20;
		case DREW_BLOCK_ENDIAN:
			return drew::SHACAL1::endian_t::GetEndianness();
		case DREW_BLOCK_KEYSIZE_LIST:
			for (drew_param_t *p = out; p; p = p->next)
				if (!strcmp(p->name, "keySize")) {
					p->param.array.ptr = (void *)shacalkeysz;
					p->param.array.len = 512/8;
				}
			return 0;
		case DREW_BLOCK_KEYSIZE_CTX:
			if (ctx && ctx->ctx) {
				const drew::SHACAL1 *p = (const drew::SHACAL1 *)ctx->ctx;
				return p->GetKeySize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::SHACAL1);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int shacal1init(drew_block_t *ctx, int flags,
		const drew_loader_t *, const drew_param_t *)
{
	using namespace drew;
	SHACAL1 *p;

	if (flags & DREW_BLOCK_FIXED)
		p = new (ctx->ctx) SHACAL1;
	else
		p = new SHACAL1;
	ctx->ctx = p;
	ctx->functbl = &shacal1functbl;
	return 0;
}

static int shacal1test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<SHACAL1>("80", 1).Test(
			"0000000000000000000000000000000000000000",
			"0ffd8d43b4e33c7c53461bd10f27a5461050d90d");
	res <<= 2;
	res |= BlockTestCase<SHACAL1>("40000000", 4).Test(
			"0000000000000000000000000000000000000000",
			"b9c60aa972b49ca04d5a0d9b9e08b2a2ba138c93");


	return res;
}

static int shacal2info(int op, void *p)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return CURRENT_ABI;
		case DREW_BLOCK_BLKSIZE:
			return 32;
		case DREW_BLOCK_KEYSIZE:
			{
				const int *x = reinterpret_cast<int *>(p);
				if (*x < 512/8)
					return *x + 1;
			}
			return 0;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::SHACAL2);
		case DREW_BLOCK_ENDIAN:
			return drew::SHACAL2::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static int shacal2info2(const drew_block_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return CURRENT_ABI;
		case DREW_BLOCK_BLKSIZE:
			return 32;
		case DREW_BLOCK_ENDIAN:
			return drew::SHACAL2::endian_t::GetEndianness();
		case DREW_BLOCK_KEYSIZE_LIST:
			for (drew_param_t *p = out; p; p = p->next)
				if (!strcmp(p->name, "keySize")) {
					p->param.array.ptr = (void *)shacalkeysz;
					p->param.array.len = DIM(shacalkeysz);
				}
			return 0;
		case DREW_BLOCK_KEYSIZE_CTX:
			if (ctx && ctx->ctx) {
				const drew::SHACAL2 *p = (const drew::SHACAL2 *)ctx->ctx;
				return p->GetKeySize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::SHACAL2);
		default:
			return -DREW_ERR_INVALID;
	}
}


static int shacal2init(drew_block_t *ctx, int flags,
		const drew_loader_t *, const drew_param_t *)
{
	using namespace drew;
	SHACAL2 *p;

	if (flags & DREW_BLOCK_FIXED)
		p = new (ctx->ctx) SHACAL2;
	else
		p = new SHACAL2;
	ctx->ctx = p;
	ctx->functbl = &shacal2functbl;
	return 0;
}

static int shacal2test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<SHACAL2>("80", 1).Test(
			"0000000000000000000000000000000000000000000000000000000000000000",
			"361ab6322fa9e7a7bb23818d839e01bddafdf47305426edd297aedb9f6202bae");
	res <<= 2;
	res |= BlockTestCase<SHACAL2>(
			"8000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			1).Test(
			"0000000000000000000000000000000000000000000000000000000000000000",
			"361ab6322fa9e7a7bb23818d839e01bddafdf47305426edd297aedb9f6202bae");
	res <<= 2;
	res |= BlockTestCase<SHACAL2>("40000000", 4).Test(
			"0000000000000000000000000000000000000000000000000000000000000000",
			"f3baf53e5301e08813f8be6f651bb19e9722151ff15063ba42a6fef7cf3bf3d7");


	return res;
}
}

typedef drew::SHACAL1::endian_t E;

drew::SHACAL1::SHACAL1()
{
}

int drew::SHACAL1::SetKeyInternal(const uint8_t *key, size_t len)
{
	uint8_t buf[512/8];
	memset(buf, 0, sizeof(buf));
	memcpy(buf, key, len);
	E::Copy(m_words, buf, sizeof(buf));
	for (size_t i = 16; i < 80; i++)
		m_words[i] = RotateLeft(m_words[i-3] ^ m_words[i-8] ^ m_words[i-14] ^
				m_words[i-16], 1);
	return 0;
}

int drew::SHACAL1::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t buf[5];
	E::Copy(buf, in, sizeof(buf));
	drew::SHA<1>::ForwardTransform(buf, m_words);
	E::Copy(out, buf, sizeof(buf));
	return 0;
}

int drew::SHACAL1::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t buf[5];
	E::Copy(buf, in, sizeof(buf));
	drew::SHA<1>::InverseTransform(buf, m_words);
	E::Copy(out, buf, sizeof(buf));
	return 0;
}

static inline uint32_t s0(uint32_t x)
{
	return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}
static inline uint32_t s1(uint32_t x)
{
	return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

drew::SHACAL2::SHACAL2()
{
}

int drew::SHACAL2::SetKeyInternal(const uint8_t *key, size_t len)
{
	uint8_t buf[512/8];
	memset(buf, 0, sizeof(buf));
	memcpy(buf, key, len);
	E::Copy(m_words, buf, sizeof(buf));
	for (size_t i = 16; i < 64; i++)
		m_words[i] = s1(m_words[i-2]) + m_words[i-7] + s0(m_words[i-15]) +
			m_words[i-16];
	return 0;
}

int drew::SHACAL2::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t buf[8];
	E::Copy(buf, in, sizeof(buf));
	drew::SHA256Transform::ForwardTransform(buf, m_words);
	E::Copy(out, buf, sizeof(buf));
	return 0;
}

int drew::SHACAL2::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t buf[8];
	E::Copy(buf, in, sizeof(buf));
	drew::SHA256Transform::InverseTransform(buf, m_words);
	E::Copy(out, buf, sizeof(buf));
	return 0;
}
UNHIDE()
