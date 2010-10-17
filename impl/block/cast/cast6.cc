#include <utility>

#include <stdio.h>
#include <string.h>

//#define DREW_TESTCASE_DEBUG 1

#include <internal.h>
#include "cast6.hh"
#include "block-plugin.hh"
#include "btestcase.hh"

extern "C" {

static const int cast6keysz[] =
{
	16, 20, 24, 28, 32
};

static int cast6_maintenance_test(void)
{
	using namespace drew;

	int result = 0;
	const char *output =
		"eea9d0a249fd3ba6b3436fb89d6dca92b2c95eb00c31ad7180ac05b8e83d696e";
	result |= BlockTestCase<CAST6>::MaintenanceTest(output, 16, 8);
	return result;
}

static int cast6test(void *, drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	const char *key128 = "2342bb9efa38542c0af75647f29f615d";
	const char *key192 = "2342bb9efa38542cbed0ac83940ac298bac77a7717942863";
	const char *key256 = "2342bb9efa38542cbed0ac83940ac298"
		"8d7c47ce264908461cc1b5137ae6b604";
	const char *pt = "00000000000000000000000000000000";

	res |= BlockTestCase<CAST6>(key128, 16).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key192, 24).Test(pt,
			"1b386c0210dcadcbdd0e41aa08a7a7e8", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key256, 32).Test(pt,
			"4f6a2038286897b9c9870136553317fa", 16);
	//res <<= 2;
	//res |= cast6_maintenance_test();

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(cast6, drew::CAST6, CAST6)
	PLUGIN_DATA_START()
	PLUGIN_DATA(cast6, "CAST-256")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}

typedef drew::CAST6::endian_t E;

drew::CAST6::CAST6()
{
}

#define W(k, tr, tm, i) do { \
	k[6] ^= f1(k[7], tm[0][i], tr[0][i]); \
	k[5] ^= f2(k[6], tm[1][i], tr[1][i]); \
	k[4] ^= f3(k[5], tm[2][i], tr[2][i]); \
	k[3] ^= f1(k[4], tm[3][i], tr[3][i]); \
	k[2] ^= f2(k[3], tm[4][i], tr[4][i]); \
	k[1] ^= f3(k[2], tm[5][i], tr[5][i]); \
	k[0] ^= f1(k[1], tm[6][i], tr[6][i]); \
	k[7] ^= f2(k[0], tm[7][i], tr[7][i]); \
} while (0)
void drew::CAST6::SetKey(const uint8_t *key, size_t sz)
{
	uint32_t keys[8];
	uint32_t cm = 0x5a827999, tm[8][24];
	uint8_t cr = 19, tr[8][24];
	const uint32_t mm = 0x6ed9eba1;
	const uint8_t mr = 17;

	memset(keys, 0, sizeof(keys));
	
	E::Copy(keys, key, sz);

	for (size_t i = 0; i < 24; i++)
		for (size_t j = 0; j < 8; j++) {
			tm[j][i] = cm;
			cm += mm;
			tr[j][i] = cr;
			cr += mr;
			cr &= 0x1f;
		}
	
	for (size_t i = 0; i < 12; i++) {
		W(keys, tr, tm, (2*i)+0);
		W(keys, tr, tm, (2*i)+1);
		m_km[0][i] = keys[7];
		m_km[1][i] = keys[5];
		m_km[2][i] = keys[3];
		m_km[3][i] = keys[1];
		m_kr[0][i] = keys[0] & 0x1f;
		m_kr[1][i] = keys[2] & 0x1f;
		m_kr[2][i] = keys[4] & 0x1f;
		m_kr[3][i] = keys[6] & 0x1f;
	}
}

#define Q(a, b, c, d, i) do { \
	c ^= f1(d, m_km[0][i], m_kr[0][i]); \
	b ^= f2(c, m_km[1][i], m_kr[1][i]); \
	a ^= f3(b, m_km[2][i], m_kr[2][i]); \
	d ^= f1(a, m_km[3][i], m_kr[3][i]); \
} while (0)
#define Qbar(a, b, c, d, i) do { \
	d ^= f1(a, m_km[3][i], m_kr[3][i]); \
	a ^= f3(b, m_km[2][i], m_kr[2][i]); \
	b ^= f2(c, m_km[1][i], m_kr[1][i]); \
	c ^= f1(d, m_km[0][i], m_kr[0][i]); \
} while (0)
#define Qi(data, i) Q(data[0], data[1], data[2], data[3], i)
#define Qbari(data, i) Qbar(data[0], data[1], data[2], data[3], i)

void drew::CAST6::Encrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t data[4];

	E::Copy(data, in, sizeof(data));

	Qi(data, 0);
	Qi(data, 1);
	Qi(data, 2);
	Qi(data, 3);
	Qi(data, 4);
	Qi(data, 5);
	Qbari(data,  6);
	Qbari(data,  7);
	Qbari(data,  8);
	Qbari(data,  9);
	Qbari(data, 10);
	Qbari(data, 11);

	E::Copy(out, data, sizeof(data));
}

void drew::CAST6::Decrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t data[4];

	E::Copy(data, in, sizeof(data));

	Qi(data, 11);
	Qi(data, 10);
	Qi(data,  9);
	Qi(data,  8);
	Qi(data,  7);
	Qi(data,  6);
	Qbari(data,  5);
	Qbari(data,  4);
	Qbari(data,  3);
	Qbari(data,  2);
	Qbari(data,  1);
	Qbari(data,  0);

	E::Copy(out, data, sizeof(data));
}

#include "sboxes.cc"
