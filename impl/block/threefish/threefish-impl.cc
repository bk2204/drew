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
 * The optimized encryption routine is from the NIST package code, which is in
 * the public domain.
 */
/* This implements Threefish-512 only. */
#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include "threefish.hh"
#include "block-plugin.hh"

typedef drew::Threefish::endian_t E;

drew::Threefish::Threefish(const uint64_t *t)
{
	memcpy(m_t, t, 16);
	m_t[2] = m_t[0] ^ m_t[1];
}

int drew::Threefish::SetKeyInternal(const uint8_t *key, size_t sz)
{
	uint64_t buf[64/8];
	const uint64_t *p;

	p = E::CopyIfNeeded(buf, key, sz);

	return SetKey(p);
}

#define ROUNDS 72
#define NS ((ROUNDS/4)+1)
#define NW 8
int drew::Threefish::SetKey(const uint64_t *k)
{
	uint64_t buf[NW + 1];

	memset(m_k, 0, sizeof(m_k));

	buf[NW] = 0x1bd11bdaa9fc1a22;

	for (size_t i = 0; i < NW; i++)
		buf[NW] ^= (buf[i] = k[i]);

	for (size_t i = 0; i < NS; i++) {
		for (size_t j = 0; j < NW; j++)
			m_k[i][j] = buf[(i+j) % (NW + 1)];
		m_k[i][NW-3] = buf[(i+(NW-3)) % (NW + 1)] + m_t[i % 3];
		m_k[i][NW-2] = buf[(i+(NW-2)) % (NW + 1)] + m_t[(i+1) % 3];
		m_k[i][NW-1] = buf[(i+(NW-1)) % (NW + 1)] + i;
	}
	return 0;
}

// Rotation constants.
const unsigned rc[8][4] = {
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44,  9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{ 8, 35, 56, 22}
};

static inline void unmix(uint64_t &y0, uint64_t &y1, unsigned rotk)
{
	y1 = RotateLeft(y1 ^ y0, rotk);
	y0 -= y1;
}

static inline void unpermute(uint64_t *y, uint64_t *x)
{
	y[2] = x[0];
	y[1] = x[1];
	y[4] = x[2];
	y[7] = x[3];
	y[6] = x[4];
	y[5] = x[5];
	y[0] = x[6];
	y[3] = x[7];
}

enum constants_t {
    R_512_0_0=46, R_512_0_1=36, R_512_0_2=19, R_512_0_3=37,
    R_512_1_0=33, R_512_1_1=27, R_512_1_2=14, R_512_1_3=42,
    R_512_2_0=17, R_512_2_1=49, R_512_2_2=36, R_512_2_3=39,
    R_512_3_0=44, R_512_3_1= 9, R_512_3_2=54, R_512_3_3=56,
    R_512_4_0=39, R_512_4_1=30, R_512_4_2=34, R_512_4_3=24,
    R_512_5_0=13, R_512_5_1=50, R_512_5_2=10, R_512_5_3=17,
    R_512_6_0=25, R_512_6_1=29, R_512_6_2=39, R_512_6_3=43,
    R_512_7_0= 8, R_512_7_1=35, R_512_7_2=56, R_512_7_3=22
};

inline void drew::Threefish::InjectKey(uint64_t *x, const size_t r) const
{
	for (size_t i = 0; i < 8; i++)
		x[i] += m_k[r][i];
}

int drew::Threefish::Encrypt(uint64_t *out, const uint64_t *in) const
{
	uint64_t x[8] ALIGNED_T;
	
	memcpy(x, in, sizeof(x));

	for (size_t i = 0, r = 0; i < (ROUNDS/8); i++, r += 2) {
		for (size_t j = 0; j < 8; j++)
			x[j] += m_k[r][j];

		x[0] += x[1]; x[1] = RotateLeft(x[1], R_512_0_0); x[1] ^= x[0];
		x[2] += x[3]; x[3] = RotateLeft(x[3], R_512_0_1); x[3] ^= x[2];
		x[4] += x[5]; x[5] = RotateLeft(x[5], R_512_0_2); x[5] ^= x[4];
		x[6] += x[7]; x[7] = RotateLeft(x[7], R_512_0_3); x[7] ^= x[6];
		
		x[2] += x[1]; x[1] = RotateLeft(x[1], R_512_1_0); x[1] ^= x[2];
		x[4] += x[7]; x[7] = RotateLeft(x[7], R_512_1_1); x[7] ^= x[4];
		x[6] += x[5]; x[5] = RotateLeft(x[5], R_512_1_2); x[5] ^= x[6];
		x[0] += x[3]; x[3] = RotateLeft(x[3], R_512_1_3); x[3] ^= x[0];
		
		x[4] += x[1]; x[1] = RotateLeft(x[1], R_512_2_0); x[1] ^= x[4];
		x[6] += x[3]; x[3] = RotateLeft(x[3], R_512_2_1); x[3] ^= x[6];
		x[0] += x[5]; x[5] = RotateLeft(x[5], R_512_2_2); x[5] ^= x[0];
		x[2] += x[7]; x[7] = RotateLeft(x[7], R_512_2_3); x[7] ^= x[2];
		
		x[6] += x[1]; x[1] = RotateLeft(x[1], R_512_3_0); x[1] ^= x[6];
		x[0] += x[7]; x[7] = RotateLeft(x[7], R_512_3_1); x[7] ^= x[0];
		x[2] += x[5]; x[5] = RotateLeft(x[5], R_512_3_2); x[5] ^= x[2];
		x[4] += x[3]; x[3] = RotateLeft(x[3], R_512_3_3); x[3] ^= x[4];

		for (size_t j = 0; j < 8; j++)
			x[j] += m_k[r+1][j];
		
		x[0] += x[1]; x[1] = RotateLeft(x[1], R_512_4_0); x[1] ^= x[0];
		x[2] += x[3]; x[3] = RotateLeft(x[3], R_512_4_1); x[3] ^= x[2];
		x[4] += x[5]; x[5] = RotateLeft(x[5], R_512_4_2); x[5] ^= x[4];
		x[6] += x[7]; x[7] = RotateLeft(x[7], R_512_4_3); x[7] ^= x[6];
		
		x[2] += x[1]; x[1] = RotateLeft(x[1], R_512_5_0); x[1] ^= x[2];
		x[4] += x[7]; x[7] = RotateLeft(x[7], R_512_5_1); x[7] ^= x[4];
		x[6] += x[5]; x[5] = RotateLeft(x[5], R_512_5_2); x[5] ^= x[6];
		x[0] += x[3]; x[3] = RotateLeft(x[3], R_512_5_3); x[3] ^= x[0];
		
		x[4] += x[1]; x[1] = RotateLeft(x[1], R_512_6_0); x[1] ^= x[4];
		x[6] += x[3]; x[3] = RotateLeft(x[3], R_512_6_1); x[3] ^= x[6];
		x[0] += x[5]; x[5] = RotateLeft(x[5], R_512_6_2); x[5] ^= x[0];
		x[2] += x[7]; x[7] = RotateLeft(x[7], R_512_6_3); x[7] ^= x[2];
		
		x[6] += x[1]; x[1] = RotateLeft(x[1], R_512_7_0); x[1] ^= x[6];
		x[0] += x[7]; x[7] = RotateLeft(x[7], R_512_7_1); x[7] ^= x[0];
		x[2] += x[5]; x[5] = RotateLeft(x[5], R_512_7_2); x[5] ^= x[2];
		x[4] += x[3]; x[3] = RotateLeft(x[3], R_512_7_3); x[3] ^= x[4];
	}

	for (size_t j = 0; j < 8; j++)
		x[j] += m_k[72/4][j];

	memcpy(out, x, sizeof(x));
	return 0;
}

int drew::Threefish::Encrypt(uint8_t *out, const uint8_t *in) const
{
	int res = 0;
	uint64_t ibuf[8], obuf[8];
	const uint64_t *ip;

	ip = E::CopyIfNeeded(ibuf, in, sizeof(ibuf));
	res = Encrypt(obuf, ip);
	E::Copy(out, obuf, sizeof(obuf));
	return res;
}

int drew::Threefish::Decrypt(uint64_t *out, const uint64_t *in) const
{
	uint64_t x[8] ALIGNED_T, y[8] ALIGNED_T;
	
	memcpy(x, in, sizeof(x));

	for (int i = (ROUNDS / 4)-1, d = 4; i >= 0; i--, d ^= 4) {
		for (int r = 1; r >= 0; r--) {
			for (size_t j = 0, k = 0; j < 8; j += 2, k++)
				unmix(x[j], x[j+1], rc[(d+r+1) & 7][k]);
			unpermute(y, x);
			for (size_t j = 0, k = 0; j < 8; j += 2, k++)
				unmix(y[j], y[j+1], rc[(d+r+0) & 7][k]);
			unpermute(x, y);
		}
		for (size_t j = 0; j < 8; j++)
			x[j] -= m_k[i][j];
	}

	memcpy(out, x, sizeof(x));
	return 0;
}

int drew::Threefish::Decrypt(uint8_t *out, const uint8_t *in) const
{
	int res = 0;
	uint64_t ibuf[8], obuf[8];
	const uint64_t *ip;

	ip = E::CopyIfNeeded(ibuf, in, sizeof(ibuf));
	res = Encrypt(obuf, ip);
	E::Copy(out, obuf, sizeof(obuf));
	return res;
}
