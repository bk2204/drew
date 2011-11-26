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
#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <drew/drew.h>
#include <drew/plugin.h>
#include <drew/stream.h>
#include "chacha.hh"
#include "stream-plugin.h"
#include "testcase.hh"

HIDE()
extern "C" {

#ifdef CHACHA_HAVE_ASM
typedef drew::ChaChaAssemblerKeystream::AlignedData chacha_ctx_t;

void chacha_asm_encrypt_bytes(chacha_ctx_t *, const uint8_t *pt, uint8_t *ct,
		uint32_t msglen);
void chacha_asm_keysetup(chacha_ctx_t *, const uint8_t *key, uint32_t keysz,
		uint32_t ivsize);
void chacha_asm_ivsetup(chacha_ctx_t *, const uint8_t *key);

static int chacha_asm_test(void *, const drew_loader_t *);
static int chacha_asm_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
#endif

static int chacha_test(void *, const drew_loader_t *);
static int chacha_info(int op, void *p);
static int chacha_info2(const drew_stream_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in);
static int chacha_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int chacha_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int chacha_reset(drew_stream_t *ctx);
static int chacha_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int chacha_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int chacha_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int chacha_encryptfast(drew_stream_t *ctx, uint8_t *out,
		const uint8_t *in, size_t len);
static int chacha_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(chacha, chacha_info, chacha_info2, chacha_init, chacha_setiv, chacha_setkey, chacha_encrypt, chacha_encrypt, chacha_encryptfast, chacha_encryptfast, chacha_test, chacha_fini, chacha_clone, chacha_reset);

#ifdef CHACHA_HAVE_ASM
PLUGIN_FUNCTBL(chacha_asm, chacha_info, chacha_info2, chacha_asm_init, chacha_setiv, chacha_setkey, chacha_encrypt, chacha_encrypt, chacha_encryptfast, chacha_encryptfast, chacha_asm_test, chacha_fini, chacha_clone, chacha_reset);
#endif

static int chacha_maintenance_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<ChaCha>("80000000000000000000000000000000", 16).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"beb1e81e0f747e43ee51922b3e87fb38d0163907b4ed49336032ab78b67c2457"
			"9fe28f751bd3703e51d876c017faa43589e63593e03355a7d57b2366f30047c5",
			64, "0000000000000000", 8);
	res <<= 4;
	res |= StreamTestCase<ChaCha>("0f62b5085bae0154a7fa4da0f34699ec"
			"3f92e5388bde3184d72a7dd02376c91c", 32).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"db165814f66733b7a8e34d1ffc1234271256d3bf8d8da2166922e598acac70f4"
			"12b3fe35a94190ad0ae2e8ec62134819ab61addcccfe99d867ca3d73183fa3fd",
			64, "288ff65dc42b92f9", 8);

	return res;
}

static int chacha_test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	res |= chacha_maintenance_test();

	return res;
}

static const int chacha_keysz[] = {16, 32};
static const int chacha_ivsz[] = {8};

static int chacha_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return CURRENT_ABI;
		case DREW_STREAM_KEYSIZE:
			for (size_t i = 0; i < DIM(chacha_keysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (chacha_keysz[i] > *x)
					return chacha_keysz[i];
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::ChaCha);
		case DREW_STREAM_BLKSIZE:
			return 64;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int chacha_info2(const drew_stream_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return CURRENT_ABI;
		case DREW_STREAM_KEYSIZE_LIST:
			for (drew_param_t *p = out; p; p = p->next)
				if (!strcmp(p->name, "keySize")) {
					p->param.array.ptr = (void *)chacha_keysz;
					p->param.array.len = DIM(chacha_keysz);
				}
			return 0;
		case DREW_STREAM_KEYSIZE_CTX:
			if (ctx && ctx->ctx) {
				const drew::ChaCha *algo = (const drew::ChaCha *)ctx->ctx;
				return algo->GetKeySize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_STREAM_IVSIZE_LIST:
			for (drew_param_t *p = out; p; p = p->next)
				if (!strcmp(p->name, "ivSize")) {
					p->param.array.ptr = (void *)chacha_ivsz;
					p->param.array.len = DIM(chacha_ivsz);
				}
			return 0;
		case DREW_STREAM_IVSIZE_CTX:
			return 8;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::ChaCha);
		case DREW_STREAM_BLKSIZE:
			return 64;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int chacha_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param)
{
	drew::ChaCha *p;
	size_t rounds = 8;

	for (const drew_param_t *pp = param; pp; pp = pp->next) {
		if (!strcmp(pp->name, "rounds"))
			rounds = pp->param.number;
	}

	rounds /= 2;

	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::ChaCha(rounds);
	else
		p = new drew::ChaCha(rounds);
	ctx->ctx = p;
	ctx->functbl = &chachafunctbl;
	return 0;
}

static int chacha_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags)
{
	drew::ChaCha *p;
	const drew::ChaCha *q = reinterpret_cast<drew::ChaCha *>(oldctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p = new (newctx->ctx) drew::ChaCha(*q);
	else
		p = new drew::ChaCha(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int chacha_reset(drew_stream_t *ctx)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	p->Reset();
	return 0;
}

static int chacha_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	p->SetNonce(key, len);
	return 0;
}

static int chacha_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	p->SetKey(key, len);
	return 0;
}

static int chacha_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int chacha_encryptfast(drew_stream_t *ctx, uint8_t *out,
		const uint8_t *in, size_t len)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	p->EncryptFast(out, in, len);
	return 0;
}

static int chacha_fini(drew_stream_t *ctx, int flags)
{
	drew::ChaCha *p = reinterpret_cast<drew::ChaCha *>(ctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p->~ChaCha();
	else 
		delete p;
	return 0;
}

#ifdef CHACHA_HAVE_ASM
static int chacha_asm_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param)
{
	drew::ChaCha *p;
	size_t rounds = 20;

	for (const drew_param_t *pp = param; pp; pp = pp->next) {
		if (!strcmp(pp->name, "rounds"))
			rounds = pp->param.number;
	}

	if (rounds != 20)
		return -DREW_ERR_INVALID;

	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::ChaCha(new drew::ChaChaAssemblerKeystream);
	else
		p = new drew::ChaCha(new drew::ChaChaAssemblerKeystream);
	ctx->ctx = p;
	ctx->functbl = &chacha_asmfunctbl;
	return 0;
}

static int chacha_asm_test(void *, const drew_loader_t *)
{
	return -DREW_ERR_NOT_IMPL;
}
#endif

PLUGIN_DATA_START()
#ifdef CHACHA_HAVE_ASM
PLUGIN_DATA(chacha_asm, "ChaCha")
#endif
PLUGIN_DATA(chacha, "ChaCha")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(chacha)

}

drew::ChaCha::ChaCha() : m_ks(new ChaChaKeystream)
{
	m_ks->SetRounds(4);
}

drew::ChaCha::ChaCha(size_t nrounds) : m_ks(new ChaChaKeystream)
{
	m_ks->SetRounds(nrounds);
}

drew::ChaCha::ChaCha(ChaChaGenericKeystream *ks) : m_ks(ks)
{
	m_ks->SetRounds(4);
}

drew::ChaCha::ChaCha(ChaChaGenericKeystream *ks, size_t nrounds) : m_ks(ks)
{
	m_ks->SetRounds(nrounds);
}

void drew::ChaCha::Reset()
{
	m_ks->Reset();
	m_nbytes = 0;
}

void drew::ChaCha::SetKey(const uint8_t *key, size_t sz)
{
	m_ks->Reset();
	m_ks->SetKey(key, sz);
	m_nbytes = 0;
}

void drew::ChaCha::SetNonce(const uint8_t *iv, size_t sz)
{
	m_ks->SetNonce(iv, sz);
}

void drew::ChaCha::EncryptFast(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXorAligned(out, in, len, m_buf, sizeof(m_buf), *m_ks);
}

void drew::ChaCha::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXor(out, in, len, m_buf, sizeof(m_buf), m_nbytes, *m_ks);
}

void drew::ChaCha::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::ChaChaKeystream::endian_t E;

drew::ChaChaKeystream::ChaChaKeystream()
{
	Reset();
	ctr = 0;
}

void drew::ChaChaKeystream::SetRounds(size_t rounds)
{
	nrounds = rounds;
}

void drew::ChaChaKeystream::SetKey(const uint8_t *key, size_t sz)
{
	keysz = sz;
	E::Copy(state.buf+4, key, sz);
	if (sz == 16)
		E::Copy(state.buf+8, key, 16);
}

void drew::ChaChaKeystream::SetNonce(const uint8_t *iv, size_t sz)
{
	E::Copy(state.buf+14, iv, sz);

	state.buf[0] = 0x61707865;
	state.buf[1] = (keysz == 16) ? 0x3120646e : 0x3320646e;
	state.buf[2] = (keysz == 16) ? 0x79622d36 : 0x79622d32;
	state.buf[3] = 0x6b206574;
}

void drew::ChaChaKeystream::Reset()
{
	ctr = 0;
}

inline void drew::ChaChaKeystream::QuarterRound(AlignedData &cur, int a, int b,
		int c, int d)
{
	cur.buf[a] += cur.buf[b];
	cur.buf[d] = RotateLeft(cur.buf[a] ^ cur.buf[d], 16);
	cur.buf[c] += cur.buf[d];
	cur.buf[b] = RotateLeft(cur.buf[b] ^ cur.buf[c], 12);
	cur.buf[a] += cur.buf[b];
	cur.buf[d] = RotateLeft(cur.buf[a] ^ cur.buf[d], 8);
	cur.buf[c] += cur.buf[d];
	cur.buf[b] = RotateLeft(cur.buf[b] ^ cur.buf[c], 7);
}

inline void drew::ChaChaKeystream::DoHash(AlignedData &cur)
{
	const AlignedData &st = state;
	memcpy(cur.buf, st.buf, 16 * sizeof(uint32_t));

	for (size_t i = 0; i < nrounds; i++) {
		QuarterRound(cur, 0, 4,  8, 12);
		QuarterRound(cur, 1, 5,  9, 13);
		QuarterRound(cur, 2, 6, 10, 14);
		QuarterRound(cur, 3, 7, 11, 15);

		QuarterRound(cur, 0, 5, 10, 15);
		QuarterRound(cur, 1, 6, 11, 12);
		QuarterRound(cur, 2, 7,  8, 13);
		QuarterRound(cur, 3, 4,  9, 14);
	}
#if defined(VECTOR_T)
	typedef int vector_t __attribute__ ((vector_size (16)));
	vector_t *curp = (vector_t *)&cur;
	const vector_t *stp = (const vector_t *)&st;
	for (size_t i = 0; i < 4; i++, curp++, stp++)
		*curp += *stp;
#else
	for (size_t i = 0; i < 16; i++)
		cur.buf[i] += st.buf[i];
#endif
}

void drew::ChaChaKeystream::FillBuffer(uint8_t buf[64])
{
	AlignedData cur;

	state.buf[12] = uint32_t(ctr);
	state.buf[13] = ctr >> 32;

	DoHash(cur);
	ctr++;
	E::Copy(buf, cur.buf, sizeof(cur.buf));
}

void drew::ChaChaKeystream::FillBufferAligned(uint8_t bufp[64])
{
	AlignedData cur;
	struct AlignedBytes
	{
		uint8_t buf[64] ALIGNED_T;
	};

	state.buf[12] = uint32_t(ctr);
	state.buf[13] = ctr >> 32;

	if (E::GetEndianness() == NativeEndian::GetEndianness()) {
		AlignedData *buf = reinterpret_cast<AlignedData *>(bufp);
		DoHash(*buf);
	}
	else {
		AlignedBytes *buf = reinterpret_cast<AlignedBytes *>(bufp);
		DoHash(cur);
		E::Copy(buf->buf, cur.buf, sizeof(cur.buf));
	}
	ctr++;
}

#ifdef CHACHA_HAVE_ASM
drew::ChaChaAssemblerKeystream::ChaChaAssemblerKeystream()
{
}

void drew::ChaChaAssemblerKeystream::SetKey(const uint8_t *key, size_t sz)
{
	chacha_asm_keysetup(&state, key, sz*8, 64);
}

void drew::ChaChaAssemblerKeystream::SetNonce(const uint8_t *iv, size_t sz)
{
	chacha_asm_ivsetup(&state, iv);
}

void drew::ChaChaAssemblerKeystream::Reset()
{
	// FIXME: implement.
}

void drew::ChaChaAssemblerKeystream::FillBuffer(uint8_t buf[64])
{
	memset(buf, 0, 64);
	chacha_asm_encrypt_bytes(&state, buf, buf, 64);
}

void drew::ChaChaAssemblerKeystream::FillBufferAligned(uint8_t bufp[64])
{
	memset(bufp, 0, 64);
	chacha_asm_encrypt_bytes(&state, bufp, bufp, 64);
}
#endif
UNHIDE()
