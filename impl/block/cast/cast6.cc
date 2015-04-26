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

//#define DREW_TESTCASE_DEBUG 1

#include <internal.h>
#include "cast6.hh"
#include "block-plugin.hh"
#include "btestcase.hh"

HIDE()
extern "C" {

static const int cast6keysz[] =
{
	16, 20, 24, 28, 32
};

static int cast6_maintenance_test(void)
{
	using namespace drew;

	int result = 0;
	result |= BlockTestCase<CAST6>::MaintenanceTest("d3f1ff988a4aa9c9c93df1382f86d"
			"be9b1dccf2eaedc95bc58d0c05fd38ea6be913276c80d5ab000e866ad49fdb03b759d"
			"c2811342fdeed899701fd5bca0ac4b", 16, 16);
	result |= BlockTestCase<CAST6>::MaintenanceTest("f36f576b0e1820d4e10e99c2fd44b"
			"1b29a264edd409f71344ba38d1295ce4229d97a89bedb4df121c2460cb704e3858ed5"
			"b3b59764430d732b5a3aafca3dd944", 24, 16);
	result |= BlockTestCase<CAST6>::MaintenanceTest("5139cab959e2e1fd019fd1a36a790"
			"564fd4b61c6ce2592f19ac817d1fcf4274028bb277c44f8b392e096410bf27cf0e517"
			"23c56ca6ffa48bf9ac2c248b4fa788", 32, 16);
	return result;
}

static int cast6test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	const char *key128 = "2342bb9efa38542c0af75647f29f615d"
		"00000000000000000000000000000000";
	const char *key192 = "2342bb9efa38542cbed0ac83940ac298"
		"bac77a77179428630000000000000000";
	const char *key256 = "2342bb9efa38542cbed0ac83940ac298"
		"8d7c47ce264908461cc1b5137ae6b604";
	const char *pt = "00000000000000000000000000000000";

	/* Since the specification for CAST6 states that keys shorter than 256 bits
	 * are padded with zeros (assuming they are multiples of 32 bits), test that
	 * to make sure it's the case.
	 */
	res |= BlockTestCase<CAST6>(key128, 16).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key128, 20).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key128, 24).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key128, 28).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key128, 32).Test(pt,
			"c842a08972b43d20836c91d1b7530f6b", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key192, 24).Test(pt,
			"1b386c0210dcadcbdd0e41aa08a7a7e8", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key192, 28).Test(pt,
			"1b386c0210dcadcbdd0e41aa08a7a7e8", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key192, 32).Test(pt,
			"1b386c0210dcadcbdd0e41aa08a7a7e8", 16);
	res <<= 2;
	res |= BlockTestCase<CAST6>(key256, 32).Test(pt,
			"4f6a2038286897b9c9870136553317fa", 16);
	res <<= 2;
	res |= cast6_maintenance_test();

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(cast6, CAST6)
	PLUGIN_DATA_START()
	PLUGIN_DATA(cast6, "CAST-256")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(cast6)
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
int drew::CAST6::SetKeyInternal(const uint8_t *key, size_t sz)
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

	return 0;
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

int drew::CAST6::Encrypt(uint8_t *out, const uint8_t *in) const
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

	return 0;
}

int drew::CAST6::Decrypt(uint8_t *out, const uint8_t *in) const
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

	return 0;
}
UNHIDE()
