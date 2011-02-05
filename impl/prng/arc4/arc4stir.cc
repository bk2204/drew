#include "arc4stir.hh"

#include <string.h>
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
 * entropy, it ensures that the state of the generator progresses rapidly.
 * This, combined with the stirring mechanism every 256 bytes, means that an
 * attacker has less information with which to predict the keystream, since many
 * of the would-be output bytes are never disclosed.
 *
 * The stirring method (key schedule in RC4) is more thorough than in standard
 * RC4.  The bytes of the seed are mixed in 256 times each and the total number
 * of iterations is 65536, which is significantly larger than the standard 256.
 * The high byte of the iteration count is also mixed in.  Whether this is
 * helpful is unknown.  The starting value of j during the mixing process is
 * again output from the generator, to avoid bias attacks.
 *
 * A final countermeasure to bias attacks is not resetting i and j whenever the
 * algorithm is stirred.  Because the Mantin-Shamir attack relies on the
 * generator output starting with i and j at zero, it is foiled.  By the time
 * that i and j are used to generate any user-visible keystream material, they
 * are already far from their original values.
 */

extern "C" {

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static int a4s_info(int op, void *p)
{
	const drew::ARC4Stir *x = reinterpret_cast<drew::ARC4Stir *>(p);
	switch (op) {
		case DREW_PRNG_VERSION:
			return 1;
		case DREW_PRNG_BLKSIZE:
			return 256;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::ARC4Stir);
		case DREW_PRNG_BLOCKING:
			return 0;
		case DREW_PRNG_ENTROPY:
			return x->GetEntropyAvailable();
		default:
			return -EINVAL;
	}
}

static int a4s_init(void **ctx, void *, int flags, drew_loader_t *, const drew_param_t *)
{
	drew::ARC4Stir *p = new drew::ARC4Stir;
	if (flags & DREW_PRNG_INIT_FIXED) {
		memcpy(*ctx, p, sizeof(*p));
		delete p;
	}
	else
		*ctx = p;
	return 0;
}

static int a4s_clone(void **newctx, void *oldctx, int flags)
{
	using namespace drew;
	ARC4Stir *p = new ARC4Stir(*reinterpret_cast<ARC4Stir *>(oldctx));
	if (flags & DREW_PRNG_CLONE_FIXED) {
		memcpy(*newctx, p, sizeof(*p));
		delete p;
	}
	else
		*newctx = p;
	return 0;
}

static int a4s_seed(void *ctx, const uint8_t *key, size_t len, size_t entropy)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int a4s_bytes(void *ctx, uint8_t *out, size_t len)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(ctx);
	p->GetBytes(out, len);
	return 0;
}

static int a4s_fini(void **ctx, int flags)
{
	drew::ARC4Stir *p = reinterpret_cast<drew::ARC4Stir *>(*ctx);
	if (flags & DREW_PRNG_FINI_NO_DEALLOC)
		p->~ARC4Stir();
	else {
		delete p;
		*ctx = NULL;
	}
	return 0;
}

static int a4s_test(void *, drew_loader_t *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_FUNCTBL(arc4stir, a4s_info, a4s_init, a4s_clone, a4s_fini, a4s_seed, a4s_bytes, a4s_test);
	PLUGIN_DATA_START()
	PLUGIN_DATA(arc4stir, "ARC4Stir")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}

drew::ARC4Stir::ARC4Stir()
{
	memcpy(m_s, pitable, 256);
	m_i = m_j = 0;
}

uint8_t drew::ARC4Stir::GetByte()
{
	uint8_t t = InternalGetByte();

	if (!m_i)
		Stir();

	m_entropy -= 8;
	return t;
}

uint8_t drew::ARC4Stir::InternalGetByte()
{
	m_i++;
	uint8_t &x = m_s[m_i];
	m_j += m_s[m_i];
	uint8_t &y = m_s[m_j];
	std::swap(x, y);
	return m_s[uint8_t(x + y)];
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

	m_entropy += entropy;
	return 0;
}

void drew::ARC4Stir::Stir()
{
	uint8_t buf[256];
	AddRandomData(buf, sizeof(buf), 0);
}

// Note that this does not reset the S-box to the initial state.
void drew::ARC4Stir::Stir(const uint8_t *k)
{
	const size_t shift = 16;
	uint8_t j = InternalGetByte();
	for (size_t i = 0; i < (1<<shift); i++) {
		const uint8_t t = i;
		const uint8_t v = (~(i >> (shift-8)) ^ t);
		j += m_s[t] + k[t] + v;
		std::swap(m_s[t], m_s[j]);
	}
}

// This table is from RC2.
const uint8_t drew::ARC4Stir::pitable[] = {
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
	0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
	0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
	0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
	0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
	0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
	0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
	0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
	0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
	0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
	0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
	0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
	0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
	0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
	0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
	0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
	0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};