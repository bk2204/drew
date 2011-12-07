/*-
 * Copyright © 2011 brian m. carlson
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
/*-
 * Because there is no official specification, this code is derived from the
 * reference code for ISAAC64, which is in the public domain.  Changes to
 * improve readability were made from the description of the original ISAAC
 * algorithm given in Jean-Philippe Aumasson's paper.
 */
#include "isaac64.hh"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#include "prng-plugin.h"

#include <algorithm>
#include <utility>

HIDE()
extern "C" {

static int isaac64_info(int op, void *p);
static int isaac64_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int isaac64_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int isaac64_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int isaac64_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int isaac64_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int isaac64_entropy(const drew_prng_t *ctx);
static int isaac64_fini(drew_prng_t *ctx, int flags);
static int isaac64_test(void *, const drew_loader_t *);

PLUGIN_FUNCTBL(isaac64, isaac64_info, isaac64_info2, isaac64_init, isaac64_clone, isaac64_fini, isaac64_seed, isaac64_bytes, isaac64_entropy, isaac64_test);

static int isaac64_info(int op, void *p)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE:
			return 2048;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::Isaac64);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int isaac64_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE_CTX:
			return 2048;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::Isaac64);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int isaac64_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::Isaac64 *p;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::Isaac64;
	else
		p = new drew::Isaac64;
	ctx->ctx = p;
	ctx->functbl = &isaac64functbl;
	return 0;
}

static int isaac64_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	using namespace drew;
	Isaac64 *p;
	const Isaac64 *q = reinterpret_cast<const Isaac64 *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) Isaac64(*q);
	else
		p = new Isaac64(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int isaac64_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::Isaac64 *p = reinterpret_cast<drew::Isaac64 *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int isaac64_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::Isaac64 *p = reinterpret_cast<drew::Isaac64 *>(ctx->ctx);
	p->GetBytes(out, len);
	return 0;
}

static int isaac64_entropy(const drew_prng_t *ctx)
{
	const drew::Isaac64 *p =
		reinterpret_cast<const drew::Isaac64 *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

static int isaac64_fini(drew_prng_t *ctx, int flags)
{
	drew::Isaac64 *p = reinterpret_cast<drew::Isaac64 *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~Isaac64();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int isaac64_test(void *, const drew_loader_t *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_DATA_START()
	PLUGIN_DATA(isaac64, "Isaac64")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(isaac64)
}

#define BUFFERSZ 256
#define LOG2BUFFERSZ 8
drew::Isaac64::Isaac64()
{
	m_aa = m_bb = m_cc = 0;
	Stir();
}

inline uint64_t drew::Isaac64::Round(uint64_t mix, uint64_t &a, uint64_t &b,
		uint64_t *s, const uint64_t *t)
{
	uint64_t x;

	x = *s;
	a = mix + *t;
	*s = a + b + m_s[uint8_t(x >> 3)];
	return b = x + m_s[uint8_t(*s >> 11)];
}

void drew::Isaac64::FillBuffer(uint64_t *r)
{
	uint64_t a, b;

	a = m_aa;
	b = m_bb + (++m_cc);

	uint64_t *s = m_s, *t = m_s + BUFFERSZ/2;

	for (size_t i = 0; i < BUFFERSZ/2; i += 4) {
		*r++ = Round(~(a ^ (a << 21)), a, b, s++, t++);
		*r++ = Round( (a ^ (a >>  5)), a, b, s++, t++);
		*r++ = Round( (a ^ (a << 12)), a, b, s++, t++);
		*r++ = Round( (a ^ (a >> 33)), a, b, s++, t++);
	}

	t = m_s;
	s = m_s + BUFFERSZ/2;

	for (size_t i = 0; i < BUFFERSZ/2; i += 4) {
		*r++ = Round(~(a ^ (a << 21)), a, b, s++, t++);
		*r++ = Round( (a ^ (a >>  5)), a, b, s++, t++);
		*r++ = Round( (a ^ (a << 12)), a, b, s++, t++);
		*r++ = Round( (a ^ (a >> 33)), a, b, s++, t++);
	}
	m_bb = b;
	m_aa = a;
}

int drew::Isaac64::GetBytes(uint8_t *buf, size_t len)
{
	size_t total = len;

	while (len) {
		size_t nbytes = std::min<size_t>(m_nbytes, len);
		const uint8_t *res = ((uint8_t *)m_res) + (sizeof(m_res)-m_nbytes);
		memcpy(buf, res, nbytes);

		m_nbytes -= nbytes;
		buf += nbytes;
		len -= nbytes;

		if (!m_nbytes) {
			FillBuffer(m_res);
			m_nbytes = sizeof(m_res);
		}
	}
	return total;
}

int drew::Isaac64::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	uint64_t tmp[256];
	const uint8_t *data = buf;
	uint8_t *t = (uint8_t *)tmp;
	
	while (len) {
		const size_t nbytes = std::min(len, sizeof(tmp));
		FillBuffer(tmp);
		for (size_t i = 0; i < sizeof(tmp); i++)
			t[i] ^= data[i % nbytes];
		Stir(tmp);
		data += nbytes;
		len -= nbytes;
	}

	return 0;
}

void drew::Isaac64::Stir()
{
	// Part of this is based on the OpenBSD arc4random PRNG.
	struct randdata {
		struct timeval tv;
		struct tms tms;
		clock_t ct;
		pid_t pid;
		ssize_t nbytes;
		uint64_t buf[BUFFERSZ];
	} rnd;
	ReliablePRNG prng;

	gettimeofday(&rnd.tv, NULL);
	rnd.ct = times(&rnd.tms);
	rnd.pid = getpid();
	rnd.nbytes = prng.GetBytes((uint8_t *)rnd.buf, sizeof(rnd.buf));
	AddRandomData((const uint8_t *)&rnd, sizeof(rnd),
			std::min<ssize_t>(rnd.nbytes, 0) * 8);
}

inline void Mix(uint64_t *t)
{
	t[0] -= t[4]; t[5] ^= t[7] >>  9; t[7] += t[0];
	t[1] -= t[5]; t[6] ^= t[0] <<  9; t[0] += t[1];
	t[2] -= t[6]; t[7] ^= t[1] >> 23; t[1] += t[2];
	t[3] -= t[7]; t[0] ^= t[2] << 15; t[2] += t[3];
	t[4] -= t[0]; t[1] ^= t[3] >> 14; t[3] += t[4];
	t[5] -= t[1]; t[2] ^= t[4] << 20; t[4] += t[5];
	t[6] -= t[2]; t[3] ^= t[5] >> 17; t[5] += t[6];
	t[7] -= t[3]; t[4] ^= t[6] << 14; t[6] += t[7];
}

// Note that this does not reset the S-box to the initial state.
void drew::Isaac64::Stir(const uint64_t *k)
{
	uint64_t t[8];

	for (size_t i = 0; i < DIM(t); i++)
		t[i] = 0x9e3779b97f4a7c13;

	for (size_t i = 0; i < 4; i++)
		Mix(t);

	for (size_t i = 0; i < BUFFERSZ; i += DIM(t)) {
		for (size_t j = 0; j < DIM(t); j++)
			t[j] += k[i+j];

		Mix(t);
		memcpy(m_s+i, t, sizeof(t));
	}

	for (size_t i = 0; i < BUFFERSZ; i += DIM(t)) {
		for (size_t j = 0; j < DIM(t); j++)
			t[j] += m_s[i+j];

		Mix(t);
		memcpy(m_s+i, t, sizeof(t));
	}

	FillBuffer(m_res);
	m_nbytes = sizeof(m_res);
}
UNHIDE()
