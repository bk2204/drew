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
#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include "safer.hh"
#include "block-plugin.hh"
#include "btestcase.hh"

HIDE()
extern "C" {

static const int saferkeysz[] =
{
	8, 16
};

static const int saferskkeysz[] =
{
	8, 16
};

static int safertest(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<SAFER>("0000000000000000", 8).Test("0000000000000000",
			"032808c90ee7ab7f");
	res <<= 2;
	res |= BlockTestCase<SAFER>("0102030405060708", 8).Test("0000000000000000",
			"5ab27f7214a33ae1");
	res <<= 2;
	res |= BlockTestCase<SAFER>("0102030405060708", 8).Test("0505050505050505",
			"a966728bbb5f5cf3");
	res <<= 2;
	res |= BlockTestCase<SAFER>("0807060504030201", 8).Test("0102030405060708",
			"c8f29cdd87783ed9");
	res <<= 2;
	res |= BlockTestCase<SAFER>(new SAFER(12),
			"08070605040302010807060504030201", 16).Test("0102030405060708",
				"dd3584a31ffb5bbb");
	res <<= 2;
	res |= BlockTestCase<SAFER>(new SAFER(12),
			"08070605040302010807060504030201", 16).Test("f8f9fafbfcfdfeff",
				"bfe1b589b8498842");

	return res;
}

static int safersktest(void *, const drew_loader_t *)
{
	using namespace drew;

	typedef BlockTestCase<SAFER_SK> BTC;

	int res = 0;

	res |= BTC("0000000000000001", 8).Test("0000000000000000",
			"fb9073d344573b0c");
	res <<= 2;
	res |= BTC("00000000000000010000000000000001", 16).Test("0000000000000000",
			"f9b0ab1bdc61bde6");

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(safer, SAFER)
	PLUGIN_STRUCTURE(safersk, SAFER_SK)
	PLUGIN_DATA_START()
	PLUGIN_DATA(safer, "SAFER-K")
	PLUGIN_DATA(safersk, "SAFER-SK")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(safer)
}

typedef drew::SAFER::endian_t E;

drew::SAFER::SAFER() : rounds(0)
{
}

drew::SAFER::SAFER(size_t r) : rounds(r)
{
}

int drew::SAFER::SetKeyInternal(const uint8_t *key, size_t sz)
{
	uint8_t r[16];

	switch (sz) {
		case 8:
			memcpy(r, key, 8);
			if (!rounds)
				rounds = 6;
			break;
		case 16:
			memcpy(r, key, 16);
			if (!rounds)
				rounds = 10;
			break;
		default:
			return -DREW_ERR_INVALID;
	}

	if (rounds > MAX_ROUNDS)
		return -DREW_ERR_NOT_IMPL;

	if (sz == 8) {
		memcpy(k[0], r, 8);
		for (unsigned i = 1; i < (2 * rounds) + 1; i++) {
			for (int j = 0; j < 8; j++) {
				r[j] = RotateLeft(r[j], 3);
				k[i][j] = r[j] + s[s[(9 * (i+1)) + j + 1]];
			}
		}
	}
	else {
		memcpy(k[0], r+8, 8);
		uint8_t *r1 = r, *r2 = r + 8;
		for (int i = 0; i < 8; i++)
			r1[i] = RotateRight(r1[i], 3);
		for (unsigned i = 1; i < (2 * rounds) + 1; i += 2) {
			for (int j = 0; j < 8; j++) {
				r1[j] = RotateLeft(r1[j], 6);
				k[i][j] = r1[j] + s[s[(9 * (i+1)) + j + 1]];
			}
			for (int j = 0; j < 8; j++) {
				r2[j] = RotateLeft(r2[j], 6);
				k[i+1][j] = r2[j] + s[s[(9 * (i+2)) + j + 1]];
			}
		}
	}
	return 0;
}

int drew::SAFER_SK::SetKeyInternal(const uint8_t *key, size_t sz)
{
	uint8_t r[18];

	switch (sz) {
		case 8:
			memcpy(r, key, 8);
			if (!rounds)
				rounds = 6;
			break;
		case 16:
			memcpy(r, key, 8);
			memcpy(r+9, key+8, 8);
			if (!rounds)
				rounds = 10;
			break;
		default:
			return -DREW_ERR_INVALID;
	}

	if (rounds > MAX_ROUNDS)
		return -DREW_ERR_NOT_IMPL;

	if (sz == 8) {
		r[8] = 0;
		for (int j = 0; j < 8; j++)
			r[8] ^= r[j];
		memcpy(k[0], r, 8);
		for (unsigned i = 1; i < (2 * rounds) + 1; i++) {
			for (int j = 0; j < 9; j++)
				r[j] = RotateLeft(r[j], 3);
			for (int j = 0; j < 8; j++)
				k[i][j] = r[(i + j) % 9] + s[s[(9 * (i+1)) + j + 1]];
		}
	}
	else {
		memcpy(k[0], r+9, 8);
		uint8_t *r1 = r, *r2 = r + 9;
		r1[8] = 0;
		r2[8] = 0;
		for (int j = 0; j < 8; j++) {
			r1[8] ^= r1[j];
			r2[8] ^= r2[j];
		}
		for (int i = 0; i < 9; i++)
			r1[i] = RotateRight(r1[i], 3);
		for (unsigned i = 1; i < (2 * rounds) + 1; i += 2) {
			for (int j = 0; j < 9; j++) {
				r1[j] = RotateLeft(r1[j], 6);
				r2[j] = RotateLeft(r2[j], 6);
			}
			for (int j = 0; j < 8; j++)
				k[i][j] = r1[(i + j) % 9] + s[s[(9 * (i+1)) + j + 1]];
			for (int j = 0; j < 8; j++)
				k[i+1][j] = r2[(i + j + 1) % 9] + s[s[(9 * (i+2)) + j + 1]];
		}
	}
	return 0;
}


inline void drew::SAFER::F(uint8_t &a, uint8_t &b, uint8_t l, uint8_t r)
{
	a = (l << 1) + r;
	b = l + r;
}

inline void drew::SAFER::FInverse(uint8_t &a, uint8_t &b, uint8_t l, uint8_t r)
{
	a = l - r;
	b = (r << 1) - l;
}

inline void drew::SAFER::ForwardA(uint8_t *x, const uint8_t *sk)
{
	x[0] ^= sk[0];
	x[1] += sk[1];
	x[2] += sk[2];
	x[3] ^= sk[3];
	x[4] ^= sk[4];
	x[5] += sk[5];
	x[6] += sk[6];
	x[7] ^= sk[7];
}

inline void drew::SAFER::InverseA(uint8_t *x, const uint8_t *sk)
{
	x[0] ^= sk[0];
	x[1] -= sk[1];
	x[2] -= sk[2];
	x[3] ^= sk[3];
	x[4] ^= sk[4];
	x[5] -= sk[5];
	x[6] -= sk[6];
	x[7] ^= sk[7];
}

inline void drew::SAFER::ForwardB(uint8_t *x, const uint8_t *sk)
{
	x[0] += sk[0];
	x[1] ^= sk[1];
	x[2] ^= sk[2];
	x[3] += sk[3];
	x[4] += sk[4];
	x[5] ^= sk[5];
	x[6] ^= sk[6];
	x[7] += sk[7];
}

inline void drew::SAFER::InverseB(uint8_t *x, const uint8_t *sk)
{
	x[0] -= sk[0];
	x[1] ^= sk[1];
	x[2] ^= sk[2];
	x[3] -= sk[3];
	x[4] -= sk[4];
	x[5] ^= sk[5];
	x[6] ^= sk[6];
	x[7] -= sk[7];
}

inline void drew::SAFER::DoF(uint8_t *x)
{
	F(x[0], x[1], x[0], x[1]);
	F(x[2], x[3], x[2], x[3]);
	F(x[4], x[5], x[4], x[5]);
	F(x[6], x[7], x[6], x[7]);
}

inline void drew::SAFER::DoFInverse(uint8_t *x)
{
	FInverse(x[0], x[1], x[0], x[1]);
	FInverse(x[2], x[3], x[2], x[3]);
	FInverse(x[4], x[5], x[4], x[5]);
	FInverse(x[6], x[7], x[6], x[7]);
}

inline void drew::SAFER::PermuteForward(uint8_t *y, const uint8_t *x)
{
	F(y[0], y[1], x[0], x[2]);
	F(y[2], y[3], x[4], x[6]);
	F(y[4], y[5], x[1], x[3]);
	F(y[6], y[7], x[5], x[7]);
}

inline void drew::SAFER::PermuteInverse(uint8_t *y, const uint8_t *x)
{
	FInverse(y[0], y[2], x[0], x[1]);
	FInverse(y[4], y[6], x[2], x[3]);
	FInverse(y[1], y[3], x[4], x[5]);
	FInverse(y[5], y[7], x[6], x[7]);
}

inline void drew::SAFER::SubstituteForward(uint8_t *x)
{
	x[0] = s[x[0]];
	x[1] = sinv[x[1]];
	x[2] = sinv[x[2]];
	x[3] = s[x[3]];
	x[4] = s[x[4]];
	x[5] = sinv[x[5]];
	x[6] = sinv[x[6]];
	x[7] = s[x[7]];
}

inline void drew::SAFER::SubstituteInverse(uint8_t *x)
{
	x[0] = sinv[x[0]];
	x[1] = s[x[1]];
	x[2] = s[x[2]];
	x[3] = sinv[x[3]];
	x[4] = sinv[x[4]];
	x[5] = s[x[5]];
	x[6] = s[x[6]];
	x[7] = sinv[x[7]];
}

int drew::SAFER::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint8_t *x = out, y[8];
	const uint8_t *sk = k[0];

	memcpy(x, in, 8);
	for (unsigned i = 0; i < rounds; i++, sk += 16) {
		ForwardA(x, sk);
		SubstituteForward(x);
		ForwardB(x, sk+8);
		DoF(x);
		PermuteForward(y, x);
		PermuteForward(x, y);
	}
	ForwardA(x, sk);
	return 0;
}

int drew::SAFER::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint8_t *x = out, y[8];
	const uint8_t *sk = k[(2 * rounds)];

	memcpy(x, in, 8);
	InverseA(x, sk);
	sk -= 16;
	for (int i = rounds - 1; i >= 0; i--, sk -= 16) {
		PermuteInverse(y, x);
		PermuteInverse(x, y);
		DoFInverse(x);
		InverseB(x, sk+8);
		SubstituteInverse(x);
		InverseA(x, sk);
	}
	return 0;
}

const uint8_t drew::SAFER::s[] = {
	0x01, 0x2d, 0xe2, 0x93, 0xbe, 0x45, 0x15, 0xae, 
	0x78, 0x03, 0x87, 0xa4, 0xb8, 0x38, 0xcf, 0x3f, 
	0x08, 0x67, 0x09, 0x94, 0xeb, 0x26, 0xa8, 0x6b, 
	0xbd, 0x18, 0x34, 0x1b, 0xbb, 0xbf, 0x72, 0xf7, 
	0x40, 0x35, 0x48, 0x9c, 0x51, 0x2f, 0x3b, 0x55, 
	0xe3, 0xc0, 0x9f, 0xd8, 0xd3, 0xf3, 0x8d, 0xb1, 
	0xff, 0xa7, 0x3e, 0xdc, 0x86, 0x77, 0xd7, 0xa6, 
	0x11, 0xfb, 0xf4, 0xba, 0x92, 0x91, 0x64, 0x83, 
	0xf1, 0x33, 0xef, 0xda, 0x2c, 0xb5, 0xb2, 0x2b, 
	0x88, 0xd1, 0x99, 0xcb, 0x8c, 0x84, 0x1d, 0x14, 
	0x81, 0x97, 0x71, 0xca, 0x5f, 0xa3, 0x8b, 0x57, 
	0x3c, 0x82, 0xc4, 0x52, 0x5c, 0x1c, 0xe8, 0xa0, 
	0x04, 0xb4, 0x85, 0x4a, 0xf6, 0x13, 0x54, 0xb6, 
	0xdf, 0x0c, 0x1a, 0x8e, 0xde, 0xe0, 0x39, 0xfc, 
	0x20, 0x9b, 0x24, 0x4e, 0xa9, 0x98, 0x9e, 0xab, 
	0xf2, 0x60, 0xd0, 0x6c, 0xea, 0xfa, 0xc7, 0xd9, 
	0x00, 0xd4, 0x1f, 0x6e, 0x43, 0xbc, 0xec, 0x53, 
	0x89, 0xfe, 0x7a, 0x5d, 0x49, 0xc9, 0x32, 0xc2, 
	0xf9, 0x9a, 0xf8, 0x6d, 0x16, 0xdb, 0x59, 0x96, 
	0x44, 0xe9, 0xcd, 0xe6, 0x46, 0x42, 0x8f, 0x0a, 
	0xc1, 0xcc, 0xb9, 0x65, 0xb0, 0xd2, 0xc6, 0xac, 
	0x1e, 0x41, 0x62, 0x29, 0x2e, 0x0e, 0x74, 0x50, 
	0x02, 0x5a, 0xc3, 0x25, 0x7b, 0x8a, 0x2a, 0x5b, 
	0xf0, 0x06, 0x0d, 0x47, 0x6f, 0x70, 0x9d, 0x7e, 
	0x10, 0xce, 0x12, 0x27, 0xd5, 0x4c, 0x4f, 0xd6, 
	0x79, 0x30, 0x68, 0x36, 0x75, 0x7d, 0xe4, 0xed, 
	0x80, 0x6a, 0x90, 0x37, 0xa2, 0x5e, 0x76, 0xaa, 
	0xc5, 0x7f, 0x3d, 0xaf, 0xa5, 0xe5, 0x19, 0x61, 
	0xfd, 0x4d, 0x7c, 0xb7, 0x0b, 0xee, 0xad, 0x4b, 
	0x22, 0xf5, 0xe7, 0x73, 0x23, 0x21, 0xc8, 0x05, 
	0xe1, 0x66, 0xdd, 0xb3, 0x58, 0x69, 0x63, 0x56, 
	0x0f, 0xa1, 0x31, 0x95, 0x17, 0x07, 0x3a, 0x28, 
};
const uint8_t drew::SAFER::sinv[] = {
	0x80, 0x00, 0xb0, 0x09, 0x60, 0xef, 0xb9, 0xfd, 
	0x10, 0x12, 0x9f, 0xe4, 0x69, 0xba, 0xad, 0xf8, 
	0xc0, 0x38, 0xc2, 0x65, 0x4f, 0x06, 0x94, 0xfc, 
	0x19, 0xde, 0x6a, 0x1b, 0x5d, 0x4e, 0xa8, 0x82, 
	0x70, 0xed, 0xe8, 0xec, 0x72, 0xb3, 0x15, 0xc3, 
	0xff, 0xab, 0xb6, 0x47, 0x44, 0x01, 0xac, 0x25, 
	0xc9, 0xfa, 0x8e, 0x41, 0x1a, 0x21, 0xcb, 0xd3, 
	0x0d, 0x6e, 0xfe, 0x26, 0x58, 0xda, 0x32, 0x0f, 
	0x20, 0xa9, 0x9d, 0x84, 0x98, 0x05, 0x9c, 0xbb, 
	0x22, 0x8c, 0x63, 0xe7, 0xc5, 0xe1, 0x73, 0xc6, 
	0xaf, 0x24, 0x5b, 0x87, 0x66, 0x27, 0xf7, 0x57, 
	0xf4, 0x96, 0xb1, 0xb7, 0x5c, 0x8b, 0xd5, 0x54, 
	0x79, 0xdf, 0xaa, 0xf6, 0x3e, 0xa3, 0xf1, 0x11, 
	0xca, 0xf5, 0xd1, 0x17, 0x7b, 0x93, 0x83, 0xbc, 
	0xbd, 0x52, 0x1e, 0xeb, 0xae, 0xcc, 0xd6, 0x35, 
	0x08, 0xc8, 0x8a, 0xb4, 0xe2, 0xcd, 0xbf, 0xd9, 
	0xd0, 0x50, 0x59, 0x3f, 0x4d, 0x62, 0x34, 0x0a, 
	0x48, 0x88, 0xb5, 0x56, 0x4c, 0x2e, 0x6b, 0x9e, 
	0xd2, 0x3d, 0x3c, 0x03, 0x13, 0xfb, 0x97, 0x51, 
	0x75, 0x4a, 0x91, 0x71, 0x23, 0xbe, 0x76, 0x2a, 
	0x5f, 0xf9, 0xd4, 0x55, 0x0b, 0xdc, 0x37, 0x31, 
	0x16, 0x74, 0xd7, 0x77, 0xa7, 0xe6, 0x07, 0xdb, 
	0xa4, 0x2f, 0x46, 0xf3, 0x61, 0x45, 0x67, 0xe3, 
	0x0c, 0xa2, 0x3b, 0x1c, 0x85, 0x18, 0x04, 0x1d, 
	0x29, 0xa0, 0x8f, 0xb2, 0x5a, 0xd8, 0xa6, 0x7e, 
	0xee, 0x8d, 0x53, 0x4b, 0xa1, 0x9a, 0xc1, 0x0e, 
	0x7a, 0x49, 0xa5, 0x2c, 0x81, 0xc4, 0xc7, 0x36, 
	0x2b, 0x7f, 0x43, 0x95, 0x33, 0xf2, 0x6c, 0x68, 
	0x6d, 0xf0, 0x02, 0x28, 0xce, 0xdd, 0x9b, 0xea, 
	0x5e, 0x99, 0x7c, 0x14, 0x86, 0xcf, 0xe5, 0x42, 
	0xb8, 0x40, 0x78, 0x2d, 0x3a, 0xe9, 0x64, 0x1f, 
	0x92, 0x90, 0x7d, 0x39, 0x6f, 0xe0, 0x89, 0x30, 
};
