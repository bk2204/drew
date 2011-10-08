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

#include <internal.h>
#include "camellia.hh"
#include "block-plugin.hh"
#include "btestcase.hh"

HIDE()
extern "C" {

static const int camelliakeysz[] =
{
	16, 24, 32
};

static int camellia128_test(void)
{
	using namespace drew;
	int res = 0;
	const char *key = "0123456789abcdeffedcba9876543210";
	res |= BlockTestCase<Camellia>(key).Test(key, "67673138549669730857065648eabe43");
	res <<= 1;
	res |= BlockTestCase<Camellia>("80000000000000000000000000000000").Test(
			"00000000000000000000000000000000",
			"6c227f749319a3aa7da235a9bba05a2c");
	return res;
}

static int camellia_big_test(void)
{
	using namespace drew;

	int res = 0;
	const char *key = "0123456789abcdeffedcba9876543210"
		"00112233445566778899aabbccddeeff";

	res |= BlockTestCase<Camellia>(key, 24).Test(key,
			"b4993401b3e996f84ee5cee7d79b09b9", 16);
	res <<= 2;
	res |= BlockTestCase<Camellia>(key, 32).Test(key,
			"9acc237dff16d76c20ef7c919e3a7509", 16);

	return res;
}

static int camellia_maintenance_test(void)
{
	using namespace drew;
	int res = 0;
	res |= BlockTestCase<Camellia>::MaintenanceTest("77beeaacb982572db94fc7536"
			"bb2336ea9439214bc626c753ee9d07b21d0fded050e4022c43fd5ccd3711f1367"
			"ce02c8fd3da2c9b016f87dab4f73983506d56f", 16, 16);
	res <<= 4;
	res |= BlockTestCase<Camellia>::MaintenanceTest("7e5c6a1d132e28dd7070154cc"
			"778586b48a07855f3a5bd04e9eeef498614cdf97fcb1e5a8a94f9a7d5940bf8d2"
			"bedb0e4ea91c1c051a6c584f172ba2ab073b7c", 24, 16);
	res <<= 4;
	res |= BlockTestCase<Camellia>::MaintenanceTest("90f262db9d51876f16f668a95"
			"6fe5772f9a98b5fb70e5651e1515947c713c0dee3419a18e7334cb3fe3328c9e2"
			"5f834e4ba9c78b15415aa6120407b3616e915c", 32, 16);
	return res;
}

static int camelliatest(void *, const drew_loader_t *)
{
	int res = 0;

	res |= camellia128_test();
	res <<= 4;
	res |= camellia_big_test();
	res <<= 12;
	res |= camellia_maintenance_test();

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(camellia, Camellia)
	PLUGIN_DATA_START()
	PLUGIN_DATA(camellia, "Camellia")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(camellia)
}

typedef drew::Camellia::endian_t E;

// Note that this function does not handle n greater than 63.  However, if you
// switch x and y and subtract 64 from n, it will work just fine.
inline void rolpair(uint64_t &a, uint64_t &b, uint64_t x, uint64_t y,
		unsigned n)
{
	a = (x << n) | (y >> (64-n));
	b = (y << n) | (x >> (64-n));
}

drew::Camellia::Camellia()
{
}

// Number of bits in a uint64_t.
#define NBITS (64)
int drew::Camellia::SetKey(const uint8_t *key, size_t sz)
{
	uint64_t ko[4];
	
	E::Copy(ko, key, sz);
	if (sz == 16)
		SetKey128(ko);
	else if (sz == 24)
		SetKey192(ko);
	else if (sz == 32)
		SetKey256(ko);
	else
		return -DREW_ERR_INVALID;
	return 0;
}

void drew::Camellia::SetKey192(uint64_t ko[4])
{
	ko[3] = ~ko[2];
	SetKey256(ko);
}

void drew::Camellia::SetKey256(uint64_t ko[4])
{
	uint64_t d1, d2;
	d1 = ko[0] ^ ko[2];
	d2 = ko[1] ^ ko[3];
	d2 ^= f(d1, 0xa09e667f3bcc908b);
	d1 ^= f(d2, 0xb67ae8584caa73b2);
	d1 ^= ko[0];
	d2 ^= ko[1];
	d2 ^= f(d1, 0xc6ef372fe94f82be);
	d1 ^= f(d2, 0x54ff53a5f1d36f1c);
	uint64_t ka[2];
	ka[0] = d1;
	ka[1] = d2;
	d1 ^= ko[2];
	d2 ^= ko[3];
	d2 ^= f(d1, 0x10e527fade682d1d);
	d1 ^= f(d2, 0xb05688c2b3e6c1fd);
	uint64_t kb[2];
	kb[0] = d1;
	kb[1] = d2;

	kw[0] = ko[0];
	kw[1] = ko[1];
	ku[0] = kb[0];
	ku[1] = kb[1];
	rolpair(ku[2], ku[3], ko[2], ko[3], 15);
	rolpair(ku[4], ku[5], ka[0], ka[1], 15);
	rolpair(kl[0], kl[1], ko[2], ko[3], 30);
	rolpair(ku[6], ku[7], kb[0], kb[1], 30);
	rolpair(ku[8], ku[9], ko[0], ko[1], 45);
	rolpair(ku[10], ku[11], ka[0], ka[1], 45);
	rolpair(kl[2], kl[3], ko[0], ko[1], 60);
	rolpair(ku[12], ku[13], ko[2], ko[3], 60);
	rolpair(ku[14], ku[15], kb[0], kb[1], 60);
	rolpair(ku[16], ku[17], ko[1], ko[0], 77-NBITS);
	rolpair(kl[4], kl[5], ka[1], ka[0], 77-NBITS);
	rolpair(ku[18], ku[19], ko[3], ko[2], 94-NBITS);
	rolpair(ku[20], ku[21], ka[1], ka[0], 94-NBITS);
	rolpair(ku[22], ku[23], ko[1], ko[0], 111-NBITS);
	rolpair(kw[2], kw[3], kb[1], kb[0], 111-NBITS);

	fenc = &Camellia::Encrypt256;
	fdec = &Camellia::Decrypt256;
}

void drew::Camellia::SetKey128(uint64_t ko[4])
{
	uint64_t d1, d2;
	d1 = ko[0];
	d2 = ko[1];
	d2 ^= f(d1, 0xa09e667f3bcc908b);
	d1 ^= f(d2, 0xb67ae8584caa73b2);
	d1 ^= ko[0];
	d2 ^= ko[1];
	d2 ^= f(d1, 0xc6ef372fe94f82be);
	d1 ^= f(d2, 0x54ff53a5f1d36f1c);
	uint64_t ka[2];
	ka[0] = d1;
	ka[1] = d2;
	uint64_t dummy;

	kw[0] = ko[0];
	kw[1] = ko[1];
	ku[0] = ka[0];
	ku[1] = ka[1];
	rolpair(ku[2], ku[3], ko[0], ko[1], 15);
	rolpair(ku[4], ku[5], ka[0], ka[1], 15);
	rolpair(kl[0], kl[1], ka[0], ka[1], 30);
	rolpair(ku[6], ku[7], ko[0], ko[1], 45);
	rolpair(ku[8], dummy, ka[0], ka[1], 45);
	rolpair(dummy, ku[9], ko[0], ko[1], 60);
	rolpair(ku[10], ku[11], ka[0], ka[1], 60);
	rolpair(kl[2], kl[3], ko[1], ko[0], 77-NBITS);
	rolpair(ku[12], ku[13], ko[1], ko[0], 94-NBITS);
	rolpair(ku[14], ku[15], ka[1], ka[0], 94-NBITS);
	rolpair(ku[16], ku[17], ko[1], ko[0], 111-NBITS);
	rolpair(kw[2], kw[3], ka[1], ka[0], 111-NBITS);

	fenc = &Camellia::Encrypt128;
	fdec = &Camellia::Decrypt128;
}

inline uint64_t drew::Camellia::f(uint64_t x, uint64_t k) const
{
	return spfunc(x ^ k);
}

inline uint64_t drew::Camellia::fl(uint64_t x, uint64_t k) const
{
	uint32_t xl = (x >> 32), xr = x, kl = (k >> 32), kr = k;

	uint32_t yr = RotateLeft(xl & kl, 1) ^ xr;
	uint32_t yl = (yr | kr) ^ xl;

	return (((uint64_t)yl) << 32) | yr;
}

inline uint64_t drew::Camellia::flinv(uint64_t y, uint64_t k) const
{
	uint32_t yl = (y >> 32), yr = y, kl = (k >> 32), kr = k;

	uint32_t xl = (yr | kr) ^ yl;
	uint32_t xr = RotateLeft(xl & kl, 1) ^ yr;

	return (((uint64_t)xl) << 32) | xr;
}

#define SP(n) s[n][E::GetByte(x, (7 - (n)))]

inline uint64_t drew::Camellia::spfunc(uint64_t x) const
{
	return SP(0) ^ SP(1) ^ SP(2) ^ SP(3) ^ SP(4) ^ SP(5) ^ SP(6) ^ SP(7);
}

int drew::Camellia::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint64_t d[2];
	E::Copy(d, in, sizeof(d));
	(this->*fenc)(d);
	E::Copy(out, d, sizeof(d));

	return 0;
}

void drew::Camellia::EncryptPair(uint64_t &x, uint64_t &y, unsigned n) const
{
	y ^= f(x, ku[n]);
	x ^= f(y, ku[n+1]);
}

void drew::Camellia::DecryptPair(uint64_t &x, uint64_t &y, unsigned n) const
{
	y ^= f(x, ku[n+1]);
	x ^= f(y, ku[n]);
}

void drew::Camellia::Encrypt128(uint64_t d[2]) const
{
	uint64_t &x = d[0], &y = d[1];

	x ^= kw[0];
	y ^= kw[1];
	EncryptPair(x, y,  0);
	EncryptPair(x, y,  2);
	EncryptPair(x, y,  4);
	x = fl(x, kl[0]);
	y = flinv(y, kl[1]);
	EncryptPair(x, y,  6);
	EncryptPair(x, y,  8);
	EncryptPair(x, y, 10);
	x = fl(x, kl[2]);
	y = flinv(y, kl[3]);
	EncryptPair(x, y, 12);
	EncryptPair(x, y, 14);
	EncryptPair(x, y, 16);
	y ^= kw[2];
	x ^= kw[3];
	std::swap(x, y);
}

void drew::Camellia::Encrypt256(uint64_t d[2]) const
{
	uint64_t &x = d[0], &y = d[1];

	x ^= kw[0];
	y ^= kw[1];
	EncryptPair(x, y,  0);
	EncryptPair(x, y,  2);
	EncryptPair(x, y,  4);
	x = fl(x, kl[0]);
	y = flinv(y, kl[1]);
	EncryptPair(x, y,  6);
	EncryptPair(x, y,  8);
	EncryptPair(x, y, 10);
	x = fl(x, kl[2]);
	y = flinv(y, kl[3]);
	EncryptPair(x, y, 12);
	EncryptPair(x, y, 14);
	EncryptPair(x, y, 16);
	x = fl(x, kl[4]);
	y = flinv(y, kl[5]);
	EncryptPair(x, y, 18);
	EncryptPair(x, y, 20);
	EncryptPair(x, y, 22);
	y ^= kw[2];
	x ^= kw[3];
	std::swap(x, y);
}

int drew::Camellia::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint64_t d[2];
	E::Copy(d, in, sizeof(d));
	(this->*fdec)(d);
	E::Copy(out, d, sizeof(d));

	return 0;
}

void drew::Camellia::Decrypt128(uint64_t d[2]) const
{
	uint64_t &x = d[0], &y = d[1];

	x ^= kw[2];
	y ^= kw[3];
	DecryptPair(x, y, 16);
	DecryptPair(x, y, 14);
	DecryptPair(x, y, 12);
	x = fl(x, kl[3]);
	y = flinv(y, kl[2]);
	DecryptPair(x, y, 10);
	DecryptPair(x, y,  8);
	DecryptPair(x, y,  6);
	x = fl(x, kl[1]);
	y = flinv(y, kl[0]);
	DecryptPair(x, y,  4);
	DecryptPair(x, y,  2);
	DecryptPair(x, y,  0);
	x ^= kw[1];
	y ^= kw[0];
	std::swap(x, y);
}

void drew::Camellia::Decrypt256(uint64_t d[2]) const
{
	uint64_t &x = d[0], &y = d[1];

	x ^= kw[2];
	y ^= kw[3];
	DecryptPair(x, y, 22);
	DecryptPair(x, y, 20);
	DecryptPair(x, y, 18);
	x = fl(x, kl[5]);
	y = flinv(y, kl[4]);
	DecryptPair(x, y, 16);
	DecryptPair(x, y, 14);
	DecryptPair(x, y, 12);
	x = fl(x, kl[3]);
	y = flinv(y, kl[2]);
	DecryptPair(x, y, 10);
	DecryptPair(x, y,  8);
	DecryptPair(x, y,  6);
	x = fl(x, kl[1]);
	y = flinv(y, kl[0]);
	DecryptPair(x, y,  4);
	DecryptPair(x, y,  2);
	DecryptPair(x, y,  0);
	x ^= kw[1];
	y ^= kw[0];
	std::swap(x, y);
}

#include "tables.cc"
UNHIDE()
