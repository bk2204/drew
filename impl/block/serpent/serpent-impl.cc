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
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "serpent.hh"

HIDE()
typedef drew::Serpent::endian_t E;

drew::Serpent::Serpent()
{
}

drew::Serpent::Serpent(const Serpent &other)
{
	m_key = m_keybuf + 8;
	memcpy(m_keybuf, other.m_keybuf, sizeof(m_keybuf));
}

#define SBOX_OUT(a, b, c, d) \
	do { x[0] = r##a; x[1] = r##b; x[2] = r##c; x[3] = r##d; } while (0)

static inline void s0(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r3 ^= r0;
	r4 = r1;
	r1 &= r3;
	r4 ^= r2;
	r1 ^= r0;
	r0 |= r3;
	r0 ^= r4;
	r4 ^= r3;
	r3 ^= r2;
	r2 |= r1;
	r2 ^= r4;
	r4 = ~r4;
	r4 |= r1;
	r1 ^= r3;
	r1 ^= r4;
	r3 |= r0;
	r1 ^= r3;
	r4 ^= r3;

	SBOX_OUT(1, 4, 2, 0);
}

static inline void s1(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r0 = ~r0;
	r2 = ~r2;
	r4 = r0;
	r0 &= r1;
	r2 ^= r0;
	r0 |= r3;
	r3 ^= r2;
	r1 ^= r0;
	r0 ^= r4;
	r4 |= r1;
	r1 ^= r3;
	r2 |= r0;
	r2 &= r4;
	r0 ^= r1;
	r1 &= r2;
	r1 ^= r0;
	r0 &= r2;
	r0 ^= r4;

	SBOX_OUT(2, 0, 3, 1);
}

static inline void s2(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r0;
	r0 &= r2;
	r0 ^= r3;
	r2 ^= r1;
	r2 ^= r0;
	r3 |= r4;
	r3 ^= r1;
	r4 ^= r2;
	r1 = r3;
	r3 |= r4;
	r3 ^= r0;
	r0 &= r1;
	r4 ^= r0;
	r1 ^= r3;
	r1 ^= r4;
	r4 = ~r4;

	SBOX_OUT(2, 3, 1, 4);
}

static inline void s3(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r0;
	r0 |= r3;
	r3 ^= r1;
	r1 &= r4;
	r4 ^= r2;
	r2 ^= r3;
	r3 &= r0;
	r4 |= r1;
	r3 ^= r4;
	r0 ^= r1;
	r4 &= r0;
	r1 ^= r3;
	r4 ^= r2;
	r1 |= r0;
	r1 ^= r2;
	r0 ^= r3;
	r2 = r1;
	r1 |= r3;
	r1 ^= r0;

	SBOX_OUT(1, 2, 3, 4);
}

static inline void s4(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r1 ^= r3;
	r3 = ~r3;
	r2 ^= r3;
	r3 ^= r0;
	r4 = r1;
	r1 &= r3;
	r1 ^= r2;
	r4 ^= r3;
	r0 ^= r4;
	r2 &= r4;
	r2 ^= r0;
	r0 &= r1;
	r3 ^= r0;
	r4 |= r1;
	r4 ^= r0;
	r0 |= r3;
	r0 ^= r2;
	r2 &= r3;
	r0 = ~r0;
	r4 ^= r2;

	SBOX_OUT(1, 4, 0, 3);
}

static inline void s5(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r0 ^= r1;
	r1 ^= r3;
	r3 = ~r3;
	r4 = r1;
	r1 &= r0;
	r2 ^= r3;
	r1 ^= r2;
	r2 |= r4;
	r4 ^= r3;
	r3 &= r1;
	r3 ^= r0;
	r4 ^= r1;
	r4 ^= r2;
	r2 ^= r0;
	r0 &= r3;
	r2 = ~r2;
	r0 ^= r4;
	r4 |= r3;
	r2 ^= r4;

	SBOX_OUT(1, 3, 0, 2);
}

static inline void s6(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r2 = ~r2;
	r4 = r3;
	r3 &= r0;
	r0 ^= r4;
	r3 ^= r2;
	r2 |= r4;
	r1 ^= r3;
	r2 ^= r0;
	r0 |= r1;
	r2 ^= r1;
	r4 ^= r0;
	r0 |= r3;
	r0 ^= r2;
	r4 ^= r3;
	r4 ^= r0;
	r3 =~ r3;
	r2 &= r4;
	r2 ^= r3;

	SBOX_OUT(0, 1, 4, 2);
}

static inline void s7(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r1;
	r1 |= r2;
	r1 ^= r3;
	r4 ^= r2;
	r2 ^= r1;
	r3 |= r4;
	r3 &= r0;
	r4 ^= r2;
	r3 ^= r1;
	r1 |= r4;
	r1 ^= r0;
	r0 |= r4;
	r0 ^= r2;
	r1 ^= r4;
	r2 ^= r1;
	r1 &= r0;
	r1 ^= r4;
	r2 = ~r2;
	r2 |= r0;
	r4 ^= r2;

	SBOX_OUT(4, 3, 1, 0);
}

static inline void si0(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r2 = ~r2;
	r4 = r1;
	r1 |= r0;
	r4 = ~r4;
	r1 ^= r2;
	r2 |= r4;
	r1 ^= r3;
	r0 ^= r4;
	r2 ^= r0;
	r0 &= r3;
	r4 ^= r0;
	r0 |= r1;
	r0 ^= r2;
	r3 ^= r4;
	r2 ^= r1;
	r3 ^= r0;
	r3 ^= r1;
	r2 &= r3;
	r4 ^= r2;

	SBOX_OUT(0, 4, 1, 3);
}

static inline void si1(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r1;
	r1 ^= r3;
	r3 &= r1;
	r4 ^= r2;
	r3 ^= r0;
	r0 |= r1;
	r2 ^= r3;
	r0 ^= r4;
	r0 |= r2;
	r1 ^= r3;
	r0 ^= r1;
	r1 |= r3;
	r1 ^= r0;
	r4 = ~r4;
	r4 ^= r1;
	r1 |= r0;
	r1 ^= r0;
	r1 |= r4;
	r3 ^= r1;

	SBOX_OUT(4, 0, 3, 2);
}

static inline void si2(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r2 ^= r3;
	r3 ^= r0;
	r4 = r3;
	r3 &= r2;
	r3 ^= r1;
	r1 |= r2;
	r1 ^= r4;
	r4 &= r3;
	r2 ^= r3;
	r4 &= r0;
	r4 ^= r2;
	r2 &= r1;
	r2 |= r0;
	r3 = ~r3;
	r2 ^= r3;
	r0 ^= r3;
	r0 &= r1;
	r3 ^= r4;
	r3 ^= r0;

	SBOX_OUT(1, 4, 2, 3);
}

static inline void si3(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r2;
	r2 ^= r1;
	r0 ^= r2;
	r4 &= r2;
	r4 ^= r0;
	r0 &= r1;
	r1 ^= r3;
	r3 |= r4;
	r2 ^= r3;
	r0 ^= r3;
	r1 ^= r4;
	r3 &= r2;
	r3 ^= r1;
	r1 ^= r0;
	r1 |= r2;
	r0 ^= r3;
	r1 ^= r4;
	r0 ^= r1;

	SBOX_OUT(2, 1, 3, 0);
}

static inline void si4(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r2;
	r2 &= r3;
	r2 ^= r1;
	r1 |= r3;
	r1 &= r0;
	r4 ^= r2;
	r4 ^= r1;
	r1 &= r2;
	r0 = ~r0;
	r3 ^= r4;
	r1 ^= r3;
	r3 &= r0;
	r3 ^= r2;
	r0 ^= r1;
	r2 &= r0;
	r3 ^= r0;
	r2 ^= r4;
	r2 |= r3;
	r3 ^= r0;
	r2 ^= r1;

	SBOX_OUT(0, 3, 2, 4);
}

static inline void si5(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r1 = ~r1;
	r4 = r3;
	r2 ^= r1;
	r3 |= r0;
	r3 ^= r2;
	r2 |= r1;
	r2 &= r0;
	r4 ^= r3;
	r2 ^= r4;
	r4 |= r0;
	r4 ^= r1;
	r1 &= r2;
	r1 ^= r3;
	r4 ^= r2;
	r3 &= r4;
	r4 ^= r1;
	r3 ^= r4;
	r4 = ~r4;
	r3 ^= r0;

	SBOX_OUT(1, 4, 3, 2);
}

static inline void si6(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r0 ^= r2;
	r4 = r2;
	r2 &= r0;
	r4 ^= r3;
	r2 = ~r2;
	r3 ^= r1;
	r2 ^= r3;
	r4 |= r0;
	r0 ^= r2;
	r3 ^= r4;
	r4 ^= r1;
	r1 &= r3;
	r1 ^= r0;
	r0 ^= r3;
	r0 |= r2;
	r3 ^= r1;
	r4 ^= r0;

	SBOX_OUT(1, 2, 4, 3);
}

static inline void si7(uint32_t *x)
{
	uint32_t r0 = x[0], r1 = x[1], r2 = x[2], r3 = x[3], r4;

	r4 = r2;
	r2 ^= r0;
	r0 &= r3;
	r4 |= r3;
	r2 = ~r2;
	r3 ^= r1;
	r1 |= r0;
	r0 ^= r2;
	r2 &= r4;
	r3 &= r4;
	r1 ^= r2;
	r2 ^= r0;
	r0 |= r2;
	r4 ^= r1;
	r0 ^= r3;
	r3 ^= r4;
	r4 |= r0;
	r3 ^= r2;
	r4 ^= r2;

	SBOX_OUT(3, 0, 1, 4);
}

int drew::Serpent::SetKeyInternal(const uint8_t *key, size_t len)
{
	uint32_t *w = m_key = m_keybuf + 8;
	memset(m_keybuf, 0, sizeof(m_keybuf));
	E::CopyCarefully(m_keybuf, key, len);
	if (len < 32)
		m_keybuf[len >> 2] |= 0x1 << ((len & 3) * 8);
	const uint32_t phi = 0x9e3779b9;
	for (int32_t i = 0; i < 132; i++)
		w[i] = RotateLeft(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ i, 11);
	for (size_t i = 0; i < 128; i += 32, w += 32) {
		s3(w+ 0);
		s2(w+ 4);
		s1(w+ 8);
		s0(w+12);
		s7(w+16);
		s6(w+20);
		s5(w+24);
		s4(w+28);
	}
	s3(w);

	return 0;
}


static inline void eround(uint32_t *b, const uint32_t *k,
		void (*s)(uint32_t *x))
{
	for (size_t i = 0; i < 4; i++)
		b[i] ^= k[i];
	s(b);
	b[0] = RotateLeft(b[0], 13);
	b[2] = RotateLeft(b[2], 3);
	b[1] = RotateLeft(b[1] ^ b[2] ^ b[0], 1);
	b[3] = RotateLeft(b[3] ^ b[2] ^ (b[0] << 3), 7);
	b[0] = RotateLeft(b[0] ^ b[3] ^ b[1], 5);
	b[2] = RotateLeft(b[2] ^ b[3] ^ (b[1] << 7), 22);
}

static inline void dround(uint32_t *b, const uint32_t *k,
		void (*s)(uint32_t *x))
{
	b[2] = RotateRight(b[2], 22);
	b[0] = RotateRight(b[0], 5);
	b[2] ^= b[3] ^ (b[1] << 7);
	b[0] ^= b[1] ^ b[3];
	b[3] = RotateRight(b[3], 7);
	b[1] = RotateRight(b[1], 1);
	b[3] ^= b[2] ^ (b[0] << 3);
	b[1] ^= b[0] ^ b[2];
	b[2] = RotateRight(b[2], 3);
	b[0] = RotateRight(b[0], 13);
	s(b);
	for (size_t i = 0; i < 4; i++)
		b[i] ^= k[i];
}

int drew::Serpent::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t b[4];
	E::Copy(b, in, sizeof(b));

	const uint32_t *k = m_key;
	for (size_t i = 0; i < 4; i++, k += 32) {
		eround(b, k+ 0, s0);
		eround(b, k+ 4, s1);
		eround(b, k+ 8, s2);
		eround(b, k+12, s3);
		eround(b, k+16, s4);
		eround(b, k+20, s5);
		eround(b, k+24, s6);
		if (i == 3)
			break;
		eround(b, k+28, s7);
	}
	k += 28;
	for (size_t i = 0; i < 4; i++)
		b[i] ^= *k++;
	s7(b);
	for (size_t i = 0; i < 4; i++) {
		b[i] ^= *k++;
	}

	E::Copy(out, b, sizeof(b));
	return 0;
}

int drew::Serpent::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t b[4];
	E::Copy(b, in, sizeof(b));

	for (size_t j = 0; j < 4; j++)
		b[j] ^= m_key[128+j];
	si7(b);
	for (size_t j = 0; j < 4; j++)
		b[j] ^= m_key[124+j];
	const uint32_t *k = m_key + (128 - 32);
	for (size_t i = 0; i < 4; i++, k -= 32) {
		if (i)
			dround(b, k+28, si7);
		dround(b, k+24, si6);
		dround(b, k+20, si5);
		dround(b, k+16, si4);
		dround(b, k+12, si3);
		dround(b, k+ 8, si2);
		dround(b, k+ 4, si1);
		dround(b, k+ 0, si0);
	}

	E::Copy(out, b, sizeof(b));
	return 0;
}

void drew::Serpent::Serpent1(uint32_t *blk)
{
	s2(blk);
}

void drew::Serpent::Serpent24(uint32_t *out, const uint8_t *in)
{
	uint32_t b[4];

	E::Copy(b, in, sizeof(b));

	const uint32_t *k = m_key;
	eround(b, k+ 0, s0);
	eround(b, k+ 4, s1);
	eround(b, k+ 8, s2);
	eround(b, k+12, s3);
	eround(b, k+16, s4);
	eround(b, k+20, s5);
	eround(b, k+24, s6);
	eround(b, k+28, s7);
	eround(b, k+32, s0);
	eround(b, k+36, s1);
	eround(b, k+40, s2);
	eround(b, k+44, s3);
	memcpy(out+0, b, sizeof(b));
	eround(b, k+48, s4);
	eround(b, k+52, s5);
	eround(b, k+56, s6);
	eround(b, k+60, s7);
	eround(b, k+64, s0);
	eround(b, k+68, s1);
	memcpy(out+4, b, sizeof(b));
	eround(b, k+72, s2);
	eround(b, k+76, s3);
	eround(b, k+80, s4);
	eround(b, k+84, s5);
	eround(b, k+88, s6);
	eround(b, k+92, s7);
	for (size_t i = 0; i < 4; i++)
		b[i] ^= k[96+i];
	memcpy(out+8, b, sizeof(b));
}
UNHIDE()
