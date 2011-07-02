#include "arc4stir.hh"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#include "prng-plugin.h"

#include <algorithm>
#include <utility>

/* This algorithm contains several differences from the standard RC4 keystream
 * generator.  First, the sbox is initialized with a different permutation of
 * the bytes 0x00-0xff, which is taken from RC2.  This helps avoid problems that
 * might occur due to the default permutation's being in order.
 *
 * Also, when data is stirred into the generator, bytes from the generator are
 * xored into the data that is used as the seed.  While this does not increase
 * entropy, it ensures that the state of the generator progresses rapidly.  The
 * generator is stirred approximately every 2**20 bytes, which is slightly more
 * conservative than the OpenBSD arc4random mechanism.
 *
 * The stirring method (key schedule in RC4) is more thorough than in standard
 * RC4.  The bytes of the seed are mixed in 256 times each and the total number
 * of iterations is 65536, which is significantly larger than the standard 256.
 * The high byte of the iteration count is also mixed in.  Whether this is
 * helpful is unknown.  The starting value of j during the mixing process is
 * again output from the generator, to avoid bias attacks.  After stirring,
 * approximately 3072 bytes (the maximum recommended by the Mironov paper) are
 * dropped, even though this should not be necessary due to the more thorough
 * mixing and more conservative design.
 *
 * A final countermeasure to bias attacks is not resetting i and j whenever the
 * algorithm is stirred.  Because the Mantin-Shamir attack relies on the
 * generator output starting with i and j at zero, it is foiled.  By the time
 * that i and j are used to generate any user-visible keystream material, they
 * are already far from their original values.
 */

// This is the largest prime less than 2**20.
#define NBYTES 1048573
// This is the smallest prime greater than 3072.
#define NDROP 3079
// This is a non-blocking random device.  If you don't have one, use /dev/null.
#define DEVICE "/dev/urandom"

extern "C" {

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

PLUGIN_FUNCTBL(arc4stir, a4s_info, a4s_init, a4s_clone, a4s_fini, a4s_seed, a4s_bytes, a4s_entropy, a4s_test);

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
			return sizeof(drew::ARC4Stir);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -EINVAL;
	}
}

static int a4s_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::ARC4Stir *p;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::ARC4Stir;
	else
		p = new drew::ARC4Stir;
	ctx->ctx = p;
	ctx->functbl = &arc4stirfunctbl;
	return 0;
}

static int a4s_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	using namespace drew;
	ARC4Stir *p;
	const ARC4Stir *q = reinterpret_cast<const ARC4Stir *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) ARC4Stir(*q);
	else
		p = new ARC4Stir(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int a4s_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int a4s_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(ctx->ctx);
	p->GetBytes(out, len);
	return 0;
}

static int a4s_entropy(const drew_prng_t *ctx)
{
	const drew::ARC4Stir *p =
		reinterpret_cast<const drew::ARC4Stir *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

static int a4s_fini(drew_prng_t *ctx, int flags)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~ARC4Stir();
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
	PLUGIN_DATA(arc4stir, "ARC4Stir")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(arc4stir)
}

drew::ARC4Stir::ARC4Stir() : m_ks(new drew::KeystreamGenerator(0))
{
	m_cnt = 0;
}

uint8_t drew::ARC4Stir::GetByte()
{
	if (--m_cnt <= 0)
		Stir();

	m_entropy -= 8;
	return InternalGetByte();
}

uint8_t drew::ARC4Stir::InternalGetByte()
{
	return m_ks->GetByte();
}

int drew::ARC4Stir::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	uint8_t tmp[256];
	const uint8_t *data = buf;
	
	while (len) {
		const size_t nbytes = std::min(len, sizeof(tmp));
		for (size_t i = 0; i < sizeof(tmp); i++)
			tmp[i] = InternalGetByte() ^ data[i % nbytes];
		Stir(tmp);
		data += nbytes;
		len -= nbytes;
	}

	for (size_t i = 0; i < NDROP; i++)
		InternalGetByte();

	m_cnt = NBYTES;
	m_entropy += entropy;
	return 0;
}

void drew::ARC4Stir::Stir()
{
	// Part of this is based on the OpenBSD arc4random PRNG.
	struct randdata {
		struct timeval tv;
		struct tms tms;
		clock_t ct;
		pid_t pid;
		int fd;
		ssize_t nbytes;
		uint8_t buf[256];
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

// Note that this does not reset the S-box to the initial state.
void drew::ARC4Stir::Stir(const uint8_t *k)
{
	m_ks->Stir(k, InternalGetByte());
}
