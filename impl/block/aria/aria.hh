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
#ifndef ARIA_HH
#define ARIA_HH

#include "internal.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "block-plugin.hh"
#include "btestcase.hh"
#include "util.hh"

HIDE()
namespace drew {

class ARIA : public BlockCipher<16>
{
	public:
		typedef BigEndian endian_t;
		ARIA();
		~ARIA() {};
		virtual int SetKey(const uint8_t *key, size_t sz) = 0;
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		typedef AlignedBlock<uint8_t, 16> AlignedData;
		void Permute(uint8_t *out, const uint8_t *in) const;
		inline void sl1(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const
		{
			AlignedData t;
			XorAligned(t.data, in.data, x.data, 16);
		
			out.data[ 0] = sb1[t.data[ 0]];
			out.data[ 1] = sb1[t.data[ 1]];
			out.data[ 2] = sb1[t.data[ 2]];
			out.data[ 3] = sb1[t.data[ 3]];
			out.data[ 4] = sb2[t.data[ 4]];
			out.data[ 5] = sb2[t.data[ 5]];
			out.data[ 6] = sb2[t.data[ 6]];
			out.data[ 7] = sb2[t.data[ 7]];
			out.data[ 8] = sb3[t.data[ 8]];
			out.data[ 9] = sb3[t.data[ 9]];
			out.data[10] = sb3[t.data[10]];
			out.data[11] = sb3[t.data[11]];
			out.data[12] = sb4[t.data[12]];
			out.data[13] = sb4[t.data[13]];
			out.data[14] = sb4[t.data[14]];
			out.data[15] = sb4[t.data[15]];
		}
		inline void sl2(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const
		{
			AlignedData t;
			XorAligned(t.data, in.data, x.data, 16);

			out.data[ 0] = sb3[t.data[ 0]];
			out.data[ 1] = sb3[t.data[ 1]];
			out.data[ 2] = sb3[t.data[ 2]];
			out.data[ 3] = sb3[t.data[ 3]];
			out.data[ 4] = sb4[t.data[ 4]];
			out.data[ 5] = sb4[t.data[ 5]];
			out.data[ 6] = sb4[t.data[ 6]];
			out.data[ 7] = sb4[t.data[ 7]];
			out.data[ 8] = sb1[t.data[ 8]];
			out.data[ 9] = sb1[t.data[ 9]];
			out.data[10] = sb1[t.data[10]];
			out.data[11] = sb1[t.data[11]];
			out.data[12] = sb2[t.data[12]];
			out.data[13] = sb2[t.data[13]];
			out.data[14] = sb2[t.data[14]];
			out.data[15] = sb2[t.data[15]];
		}
		inline uint8_t combine(const AlignedData &d, unsigned v1, unsigned v2,
				unsigned v3, unsigned v4, unsigned v5, unsigned v6,
				unsigned v7) const;
		inline void afunc(AlignedData &out, const AlignedData &in) const
		{
			const uint8_t p349e = in.data[12] ^ in.data[1] ^ in.data[6] ^ in.data[11];
			const uint8_t p0b = in.data[0] ^ in.data[14];
			const uint8_t p1a = in.data[4] ^ in.data[10];
			const uint8_t p6d = in.data[9] ^ in.data[7];
			const uint8_t p7c = in.data[13] ^ in.data[3];
			out.data[11] = p349e ^ p0b ^ in.data[5];
			out.data[ 5] = p349e ^ p1a ^ in.data[15];
			out.data[ 0] = p349e ^ p6d ^ in.data[2];
			out.data[14] = p349e ^ p7c ^ in.data[8];
		
			const uint8_t p258f = in.data[8] ^ in.data[5] ^ in.data[2] ^ in.data[15];
			out.data[ 1] = p258f ^ p0b ^ in.data[11];
			out.data[15] = p258f ^ p1a ^ in.data[1];
			out.data[10] = p258f ^ p6d ^ in.data[12];
			out.data[ 4] = p258f ^ p7c ^ in.data[6];
		
			const uint8_t p16bc = in.data[4] ^ in.data[9] ^ in.data[14] ^ in.data[3];
			const uint8_t p29 = in.data[8] ^ in.data[6];
			const uint8_t p38 = in.data[12] ^ in.data[2];
			const uint8_t p4f = in.data[1] ^ in.data[15];
			const uint8_t p5e = in.data[5] ^ in.data[11];
			out.data[ 3] = p16bc ^ p29 ^ in.data[13];
			out.data[13] = p16bc ^ p38 ^ in.data[7];
			out.data[ 8] = p16bc ^ p4f ^ in.data[10];
			out.data[ 6] = p16bc ^ p5e ^ in.data[0];
		
			const uint8_t p07ad = in.data[0] ^ in.data[13] ^ in.data[10] ^ in.data[7];
			out.data[ 9] = p07ad ^ p29 ^ in.data[3];
			out.data[ 7] = p07ad ^ p38 ^ in.data[9];
			out.data[ 2] = p07ad ^ p4f ^ in.data[4];
			out.data[12] = p07ad ^ p5e ^ in.data[14];
		}
		inline void fo(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const
		{
			AlignedData t;
			sl1(t, in, x);
			afunc(out, t);
		}
		inline void fe(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const
		{
			AlignedData t;
			sl2(t, in, x);
			afunc(out, t);
		}
		int Encrypt128(uint8_t *, const uint8_t *, const AlignedData *) const;
		int Encrypt192(uint8_t *, const uint8_t *, const AlignedData *) const;
		int Encrypt256(uint8_t *, const uint8_t *, const AlignedData *) const;
		AlignedData m_ek[17], m_dk[17];
		size_t m_off;
		static const uint8_t sb1[], sb2[], sb3[], sb4[];
	private:

};

#if defined(ARIA_128) && defined(FEATURE_128_BIT_INTEGERS)
// This will only work on targets where 128-bit quantities exist.
class ARIA128 : public ARIA
{
	public:
		int SetKey(const uint8_t *key, size_t sz);
	protected:
		typedef unsigned __int128 uint128_t;
		uint128_t fo128(uint128_t a, uint128_t b) const;
		uint128_t fe128(uint128_t a, uint128_t b) const;
};
#elif defined(ARIA_BYTEWISE)
class ARIABytewise : public ARIA
{
	public:
		int SetKey(const uint8_t *key, size_t sz);
	protected:
		void RotateRightAndXor(AlignedData &out, const AlignedData &in,
				const AlignedData &x, size_t offset) const;
};
#endif

}

template<class T>
static int test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	const char *key = "000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f";
	const char *pt = "00112233445566778899aabbccddeeff";

	res |= BlockTestCase<T>(key, 16).Test(pt,
			"d718fbd6ab644c739da95f3be6451778");
	res <<= 2;
	res |= BlockTestCase<T>(key, 24).Test(pt,
			"26449c1805dbe7aa25a468ce263a9e79");
	res <<= 2;
	res |= BlockTestCase<T>(key, 32).Test(pt,
			"f92bd7c79fb72e2f2b8f80c1972d24fc");

	return res;
}

extern "C" {
static const int ariakeysz[] =
{
	16, 24, 32
};
}
UNHIDE()

#endif
