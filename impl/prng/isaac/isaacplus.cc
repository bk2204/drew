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
#include "isaacplus.hh"

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

static int isaacplus_info(int op, void *p);
static int isaacplus_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int isaacplus_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int isaacplus_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int isaacplus_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int isaacplus_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int isaacplus_entropy(const drew_prng_t *ctx);
static int isaacplus_fini(drew_prng_t *ctx, int flags);
static int isaacplus_test(void *, const drew_loader_t *);

PLUGIN_FUNCTBL(isaacplus, isaacplus_info, isaacplus_info2, isaacplus_init, isaacplus_clone, isaacplus_fini, isaacplus_seed, isaacplus_bytes, isaacplus_entropy, isaacplus_test);

static int isaacplus_info(int op, void *p)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE:
			return 1024;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::IsaacPlus);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int isaacplus_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE_CTX:
			return 1024;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::IsaacPlus);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

static int isaacplus_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::IsaacPlus *p;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::IsaacPlus;
	else
		p = new drew::IsaacPlus;
	ctx->ctx = p;
	ctx->functbl = &isaacplusfunctbl;
	return 0;
}

static int isaacplus_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	using namespace drew;
	IsaacPlus *p;
	const IsaacPlus *q = reinterpret_cast<const IsaacPlus *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) IsaacPlus(*q);
	else
		p = new IsaacPlus(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int isaacplus_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::IsaacPlus *p = reinterpret_cast<drew::IsaacPlus *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int isaacplus_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::IsaacPlus *p = reinterpret_cast<drew::IsaacPlus *>(ctx->ctx);
	p->GetBytes(out, len);
	return 0;
}

static int isaacplus_entropy(const drew_prng_t *ctx)
{
	const drew::IsaacPlus *p =
		reinterpret_cast<const drew::IsaacPlus *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

static int isaacplus_fini(drew_prng_t *ctx, int flags)
{
	drew::IsaacPlus *p = reinterpret_cast<drew::IsaacPlus *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~IsaacPlus();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int isaacplus_test(void *, const drew_loader_t *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_DATA_START()
	PLUGIN_DATA(isaacplus, "Isaac+")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(isaacplus)
}

#define BUFFERSZ 256
#define LOG2BUFFERSZ 8
drew::IsaacPlus::IsaacPlus()
{
	m_aa = m_bb = m_cc = 0;
	Stir();
}

inline uint32_t drew::IsaacPlus::Round(uint32_t mix, uint32_t &a, uint32_t &b,
		uint32_t *s, const uint32_t *t)
{
	uint32_t x;

	x = *s;
	a = mix + *t;
	*s = a ^ (b + m_s[uint8_t(x >> 2)]);
	return b = x + (a ^ m_s[uint8_t(*s >> 10)]);
}

void drew::IsaacPlus::FillBuffer(uint32_t *r)
{
	uint32_t a, b;

	a = m_aa;
	b = m_bb + (++m_cc);

	uint32_t *s = m_s, *t = m_s + BUFFERSZ/2;

	for (size_t i = 0; i < BUFFERSZ/2; i += 4) {
		*r++ = Round(RotateLeft(a,  13), a, b, s++, t++);
		*r++ = Round(RotateRight(a,  6), a, b, s++, t++);
		*r++ = Round(RotateLeft(a,   2), a, b, s++, t++);
		*r++ = Round(RotateRight(a, 16), a, b, s++, t++);
	}

	t = m_s;
	s = m_s + BUFFERSZ/2;

	for (size_t i = 0; i < BUFFERSZ/2; i += 4) {
		*r++ = Round(RotateLeft(a,  13), a, b, s++, t++);
		*r++ = Round(RotateRight(a,  6), a, b, s++, t++);
		*r++ = Round(RotateLeft(a,   2), a, b, s++, t++);
		*r++ = Round(RotateRight(a, 16), a, b, s++, t++);
	}
	m_bb = b;
	m_aa = a;
}

int drew::IsaacPlus::GetBytes(uint8_t *buf, size_t len)
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

int drew::IsaacPlus::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	uint32_t tmp[256];
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

void drew::IsaacPlus::Stir()
{
	// Part of this is based on the OpenBSD arc4random PRNG.
	struct randdata {
		struct timeval tv;
		struct tms tms;
		clock_t ct;
		pid_t pid;
		ssize_t nbytes;
		uint32_t buf[BUFFERSZ];
	} rnd;
	ReliablePRNG prng;

	gettimeofday(&rnd.tv, NULL);
	rnd.ct = times(&rnd.tms);
	rnd.pid = getpid();
	rnd.nbytes = prng.GetBytes((uint8_t *)rnd.buf, sizeof(rnd.buf));
	AddRandomData((const uint8_t *)&rnd, sizeof(rnd),
			std::min<ssize_t>(rnd.nbytes, 0) * 8);
}

inline void Mix(uint32_t *t)
{
	t[0] ^= t[1] << 11; t[4] += t[0]; t[1] += t[2];
	t[1] ^= t[2] >>  2; t[5] += t[1]; t[2] += t[3];
	t[2] ^= t[3] <<  8; t[6] += t[2]; t[3] += t[4];
	t[3] ^= t[4] >> 16; t[7] += t[3]; t[4] += t[5];
	t[4] ^= t[5] << 10; t[0] += t[4]; t[5] += t[6];
	t[5] ^= t[6] >>  4; t[1] += t[5]; t[6] += t[7];
	t[6] ^= t[7] <<  8; t[2] += t[6]; t[7] += t[0];
	t[7] ^= t[0] >>  9; t[3] += t[7]; t[0] += t[1];
}

// Note that this does not reset the S-box to the initial state.
void drew::IsaacPlus::Stir(const uint32_t *k)
{
	uint32_t t[8];

	for (size_t i = 0; i < DIM(t); i++)
		t[i] = 0x9e3779b9;

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
