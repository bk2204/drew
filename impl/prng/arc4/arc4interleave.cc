#include "arc4interleave.hh"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#include "prng-plugin.h"

#include <algorithm>
#include <utility>

/* This is essentially the same algorithm as in the arc4stir module, except that
 * four keystream generators are used, each one having a different initial
 * permutations.  Each keystream generator outputs a byte in turn.  The major
 * difference is that when stirring in random data, the states of the generators
 * are intertwined because of the interleaving.
 */

// This is the largest prime less than 2**21.
#define NBYTES 2097143
// This is the smallest prime greater than 3072 * 2.
#define NDROP 6151
// This is a non-blocking random device.  If you don't have one, use /dev/null.
#define DEVICE "/dev/urandom"

extern "C" {

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static int a4s_info(int op, void *p);
static int a4s_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int a4s_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int a4s_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int a4s_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int a4s_entropy(const drew_prng_t *ctx);
static int a4s_fini(drew_prng_t *ctx, int flags);
static int a4s_test(void *, const drew_loader_t *);

PLUGIN_FUNCTBL(arc4interleave, a4s_info, a4s_init, a4s_clone, a4s_fini, a4s_seed, a4s_bytes, a4s_entropy, a4s_test);

static int a4s_info(int op, void *p)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return 2;
		case DREW_PRNG_BLKSIZE:
			return 256;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::ARC4Interleave);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -EINVAL;
	}
}

static int a4s_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::ARC4Interleave *p;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::ARC4Interleave;
	else
		p = new drew::ARC4Interleave;
	ctx->ctx = p;
	ctx->functbl = &arc4interleavefunctbl;
	return 0;
}

static int a4s_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	using namespace drew;
	ARC4Interleave *p;
	const ARC4Interleave *q = reinterpret_cast<const ARC4Interleave *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) ARC4Interleave(*q);
	else
		p = new ARC4Interleave(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int a4s_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::ARC4Interleave *p = reinterpret_cast<drew::ARC4Interleave *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int a4s_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::ARC4Interleave *p = reinterpret_cast<drew::ARC4Interleave *>(ctx->ctx);
	p->GetBytes(out, len);
	return 0;
}

static int a4s_entropy(const drew_prng_t *ctx)
{
	const drew::ARC4Interleave *p =
		reinterpret_cast<const drew::ARC4Interleave *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

static int a4s_fini(drew_prng_t *ctx, int flags)
{
	drew::ARC4Interleave *p = reinterpret_cast<drew::ARC4Interleave *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~ARC4Interleave();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int a4s_test(void *, const drew_loader_t *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_DATA_START()
	PLUGIN_DATA(arc4interleave, "ARC4Interleave")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}

drew::ARC4Interleave::ARC4Interleave()
{
	for (int i = 0; i < 4; i++)
		m_ks[i] = new KeystreamGenerator(i);
	m_index = 0;
	m_cnt = 0;
}

uint8_t drew::ARC4Interleave::GetByte()
{
	if (--m_cnt <= 0)
		Stir();

	m_entropy -= 8;
	return InternalGetByte();
}

uint8_t drew::ARC4Interleave::InternalGetByte()
{
	uint8_t b1 = m_ks[m_index & 3]->GetByte();
	m_index++;
	return b1 ^ m_ks[m_index & 3]->GetByte();
}

int drew::ARC4Interleave::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	uint8_t tmp[1024];
	const uint8_t *data = buf;
	
	while (len) {
		const size_t nbytes = std::min(len, sizeof(tmp));
		for (size_t i = 0; i < sizeof(tmp); i++)
			tmp[i] = InternalGetByte() ^ data[i % nbytes];
		m_ks[0]->Stir(tmp +   0, InternalGetByte());
		m_ks[1]->Stir(tmp + 256, InternalGetByte());
		m_ks[2]->Stir(tmp + 512, InternalGetByte());
		m_ks[3]->Stir(tmp + 768, InternalGetByte());
		data += nbytes;
		len -= nbytes;
	}

	for (size_t i = 0; i < NDROP; i++)
		InternalGetByte();

	m_cnt = NBYTES;
	m_entropy += entropy;
	return 0;
}

void drew::ARC4Interleave::Stir()
{
	// Part of this is based on the OpenBSD arc4random PRNG.
	struct randdata {
		struct timeval tv;
		struct tms tms;
		clock_t ct;
		pid_t pid;
		int fd;
		ssize_t nbytes;
		uint8_t buf[1024];
	} rnd;

	gettimeofday(&rnd.tv, NULL);
	rnd.ct = times(&rnd.tms);
	rnd.pid = getpid();
	rnd.nbytes = 0;
	if ((rnd.fd = open(DEVICE, O_RDONLY)) >= 0) {
		rnd.nbytes = read(rnd.fd, rnd.buf, sizeof(rnd.buf));
		close(rnd.fd);
	}
	AddRandomData((const uint8_t *)&rnd, sizeof(rnd),
			std::min<ssize_t>(rnd.nbytes, 0) * 8);
}

#include "keystream.cc"
