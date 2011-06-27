#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include "cast5.hh"
#include "block-plugin.hh"
#include "btestcase.hh"

extern "C" {

static const int cast5keysz[] =
{
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

static int cast5_maintenance_test(void)
{
	using namespace drew;

	int result = 0;
	const char *output =
		"eea9d0a249fd3ba6b3436fb89d6dca92b2c95eb00c31ad7180ac05b8e83d696e";
	result |= BlockTestCase<CAST5>::MaintenanceTest(output, 16, 8);
	return result;
}

static int cast5test(void *, const drew_loader_t *)
{
	using namespace drew;

	int result = 0;
	uint8_t k128[] = {
		0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
		0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
	};
	uint8_t p128[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
	};
	uint8_t c128[] = {
		0x23, 0x8b, 0x4f, 0xe5, 0x84, 0x7e, 0x44, 0xb2
	};
	uint8_t c80[] = {
		0xeb, 0x6a, 0x71, 0x1a, 0x2c, 0x02, 0x27, 0x1b
	};
	uint8_t c40[] = {
		0x7a, 0xc8, 0x16, 0xd1, 0x6e, 0x9b, 0x30, 0x2e
	};
	uint8_t buf[8];

	CAST5 ctx;
	ctx.SetKey(k128, 16);
	ctx.Encrypt(buf, p128);
	result |= !!memcmp(buf, c128, sizeof(buf));
	result <<= 1;
	ctx.Decrypt(buf, c128);
	result |= !!memcmp(buf, p128, sizeof(buf));
	result <<= 1;

	ctx.SetKey(k128, 10);
	ctx.Encrypt(buf, p128);
	result |= !!memcmp(buf, c80, sizeof(buf));
	result <<= 1;
	ctx.Decrypt(buf, c80);
	result |= !!memcmp(buf, p128, sizeof(buf));
	result <<= 1;

	ctx.SetKey(k128, 5);
	ctx.Encrypt(buf, p128);
	result |= !!memcmp(buf, c40, sizeof(buf));
	result <<= 1;
	ctx.Decrypt(buf, c40);
	result |= !!memcmp(buf, p128, sizeof(buf));
	result <<= 2;

	result |= cast5_maintenance_test();

	return result;
}

}

extern "C" {
	PLUGIN_STRUCTURE(cast5, CAST5)
	PLUGIN_DATA_START()
	PLUGIN_DATA(cast5, "CAST-128")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(cast5)
}

drew::CAST5::CAST5()
{
}

int drew::CAST5::SetKey(const uint8_t *key, size_t sz)
{
	// We copy into this buffer because we're going to load this into a buffer
	// of uint32_ts, but the key size only has to be a multiple of 8 bits.
	uint8_t buf[128/8];
	memset(buf, 0, sizeof(buf));
	memcpy(buf, key, sz);
	m_longkey = (sz > (80 / 8));
	ComputeSubkeys(buf);
	memset(buf, 0, sizeof(buf));
	return 0;
}

#define sx(a, b) m_s[a][endian_t::GetArrayByte(x, (b ^ 3))]
#define sz(a, b) m_s[a][endian_t::GetArrayByte(z, (b ^ 3))]

void drew::CAST5::ComputeZSet(uint32_t *z, const uint32_t *x)
{
	z[0] = x[0] ^ sx(4, 13) ^ sx(5, 15) ^ sx(6, 12) ^ sx(7, 14) ^ sx(6,  8);
	z[1] = x[2] ^ sz(4,  0) ^ sz(5,  2) ^ sz(6,  1) ^ sz(7,  3) ^ sx(7, 10);
	z[2] = x[3] ^ sz(4,  7) ^ sz(5,  6) ^ sz(6,  5) ^ sz(7,  4) ^ sx(4,  9);
	z[3] = x[1] ^ sz(4, 10) ^ sz(5,  9) ^ sz(6, 11) ^ sz(7,  8) ^ sx(5, 11);
}

void drew::CAST5::ComputeXSet(uint32_t *x, const uint32_t *z)
{
	x[0] = z[2] ^ sz(4,  5) ^ sz(5,  7) ^ sz(6,  4) ^ sz(7,  6) ^ sz(6,  0);
	x[1] = z[0] ^ sx(4,  0) ^ sx(5,  2) ^ sx(6,  1) ^ sx(7,  3) ^ sz(7,  2);
	x[2] = z[1] ^ sx(4,  7) ^ sx(5,  6) ^ sx(6,  5) ^ sx(7,  4) ^ sz(4,  1);
	x[3] = z[3] ^ sx(4, 10) ^ sx(5,  9) ^ sx(6, 11) ^ sx(7,  8) ^ sz(5,  3);
}

void drew::CAST5::ComputeSubkeySetA(uint32_t *sk, const uint32_t *z, uint8_t a,
		uint8_t b, uint8_t c, uint8_t d)
{
	sk[0] = sz(4,  8) ^ sz(5,  9) ^ sz(6,  7) ^ sz(7,  6) ^ sz(4, a);
	sk[1] = sz(4, 10) ^ sz(5, 11) ^ sz(6,  5) ^ sz(7,  4) ^ sz(5, b);
	sk[2] = sz(4, 12) ^ sz(5, 13) ^ sz(6,  3) ^ sz(7,  2) ^ sz(6, c);
	sk[3] = sz(4, 14) ^ sz(5, 15) ^ sz(6,  1) ^ sz(7,  0) ^ sz(7, d);
}

void drew::CAST5::ComputeSubkeySetB(uint32_t *sk, const uint32_t *z, uint8_t a,
		uint8_t b, uint8_t c, uint8_t d)
{
	sk[0] = sz(4,  3) ^ sz(5,  2) ^ sz(6, 12) ^ sz(7, 13) ^ sz(4, a);
	sk[1] = sz(4,  1) ^ sz(5,  0) ^ sz(6, 14) ^ sz(7, 15) ^ sz(5, b);
	sk[2] = sz(4,  7) ^ sz(5,  6) ^ sz(6,  8) ^ sz(7,  9) ^ sz(6, c);
	sk[3] = sz(4,  5) ^ sz(5,  4) ^ sz(6, 10) ^ sz(7, 11) ^ sz(7, d);
}

void drew::CAST5::ComputeSubkeys(const uint8_t *k)
{
	uint32_t z[4];
	uint32_t x[4];
	uint32_t sk[32];

	endian_t::Copy(x, k, sizeof(x));

	for (size_t i = 0; i < 32; i += 16) {
		// Endianness issues are taken care of by m_perm.
		ComputeZSet(z, x);
		ComputeSubkeySetA(sk+i   , z, 2, 6, 9, 12);
		ComputeXSet(x, z);
		ComputeSubkeySetB(sk+i+ 4, x, 8, 13, 3, 7);
		ComputeZSet(z, x);
		ComputeSubkeySetB(sk+i+ 8, z, 9, 12, 2, 6);
		ComputeXSet(x, z);
		ComputeSubkeySetA(sk+i+12, x, 3, 7, 8, 13);
	}

	for (size_t i = 0; i < 16; i++) {
		m_km[i] = sk[i];
		m_kr[i] = sk[i+16] & 0x1f;
	}
}

int drew::CAST5::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t l, r;
	size_t iters = m_longkey ? 15 : 12;

	endian_t::Copy(&l, in+0, sizeof(l));
	endian_t::Copy(&r, in+4, sizeof(r));

	for (size_t i = 0; i < iters; i += 3) {
		l ^= f1(r, m_km[i+0], m_kr[i+0]);
		std::swap(l, r);
		l ^= f2(r, m_km[i+1], m_kr[i+1]);
		std::swap(l, r);
		l ^= f3(r, m_km[i+2], m_kr[i+2]);
		std::swap(l, r);
	}
	if (m_longkey)
		l ^= f1(r, m_km[15], m_kr[15]);
	else
		std::swap(l, r);

	endian_t::Copy(out+0, &l, sizeof(l));
	endian_t::Copy(out+4, &r, sizeof(r));

	return 0;
}

int drew::CAST5::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t l, r;
	int initial = m_longkey ? 14 : 11;

	endian_t::Copy(&l, in+0, sizeof(l));
	endian_t::Copy(&r, in+4, sizeof(r));

	if (m_longkey) {
		l ^= f1(r, m_km[15], m_kr[15]);
		std::swap(l, r);
	}
	for (int i = initial; i > 0; i -= 3) {
		l ^= f3(r, m_km[i-0], m_kr[i-0]);
		std::swap(l, r);
		l ^= f2(r, m_km[i-1], m_kr[i-1]);
		std::swap(l, r);
		l ^= f1(r, m_km[i-2], m_kr[i-2]);
		std::swap(l, r);
	}

	endian_t::Copy(out+0, &r, sizeof(l));
	endian_t::Copy(out+4, &l, sizeof(r));

	return 0;
}
