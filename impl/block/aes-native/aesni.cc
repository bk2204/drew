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

#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.h"
#include "aes.hh"

HIDE()
inline bool HasAESNI()
{
#if defined(__i386__) || defined(__amd64__)
	int res = 0;
	uint32_t a, b, c, d;
	res = GetCpuid(1, a, b, c, d);
	if (res)
		return false;
	return c & 0x02000000;
#else
	return false;
#endif
}

#ifdef FEATURE_AESNI
#define NATIVE_IMPLEMENTED
#endif

#ifdef NATIVE_IMPLEMENTED
namespace drew {
	typedef AESNI AESImpl;
}
#endif
#include "aes-misc.cc"
extern "C" {
EXPORT()
int DREW_PLUGIN_NAME(aesni)(void *ldr, int op, int id, void *p) 
{ 
	int nplugins = HasAESNI() ? sizeof(plugin_data)/sizeof(plugin_data[0]) : 0;
	if (id < 0 || id >= nplugins) {
		if (!id && !nplugins && op == DREW_LOADER_GET_NPLUGINS)
			return 0;
		else
			return -DREW_ERR_INVALID;
	}
	switch (op) { 
		case DREW_LOADER_LOOKUP_NAME: 
			return 0; 
		case DREW_LOADER_GET_NPLUGINS: 
			return nplugins; 
		case DREW_LOADER_GET_TYPE: 
			return DREW_TYPE_BLOCK; 
		case DREW_LOADER_GET_FUNCTBL_SIZE: 
			return sizeof(drew_block_functbl_t); 
		case DREW_LOADER_GET_FUNCTBL: 
			memcpy(p, plugin_data[id].functbl, sizeof(drew_block_functbl_t)); 
			return 0; 
		case DREW_LOADER_GET_NAME_SIZE: 
			return strlen(plugin_data[id].name) + 1; 
		case DREW_LOADER_GET_NAME: 
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1); 
			return 0; 
		default: 
			return -DREW_ERR_INVALID; 
	} 
}
UNEXPORT()
}

#ifdef FEATURE_AESNI
drew::AESNI::AESNI()
{
}

int drew::AESNI::SetKeyInternal(const uint8_t *key, size_t len)
{
	switch (len) {
		case 16:
		case 24:
		case 32:
			break;
		case 20:
		case 28:
			return -DREW_ERR_NOT_IMPL;
		default:
			return -DREW_ERR_INVALID;
	}
	m_nk = (len / 4);
	m_nr = 6 + std::max(m_nb, m_nk);

	SetKeyEncrypt(key, len);
	SetKeyDecrypt();
	return 0;
}

typedef drew::AESNI::vector_t vector_t;
typedef drew::AESNI::vector4i_t vector4i_t;

/* This key scheduling algorithm is from Crypto++. */
void drew::AESNI::SetKeyEncrypt(const uint8_t *key, size_t len)
{
	const size_t shortlen = len / 4;
	uint32_t *rk = (uint32_t *)m_rk, *rko;
	vector_t t;
	const uint8_t *rc = rcon;
	memcpy(&t, key+len-16, 16);
	memcpy(rk, key, len);
	rko = rk;

	for (;; rk += shortlen) {
		vector_t t2;
		t2 = __builtin_ia32_aeskeygenassist128(t, 0);
		rk[shortlen+0] = rk[0] ^
			__builtin_ia32_vec_ext_v4si(vector4i_t(t2), 3) ^ *(rc++);
		rk[shortlen+1] = rk[1] ^ rk[shortlen+0];
		rk[shortlen+2] = rk[2] ^ rk[shortlen+1];
		rk[shortlen+3] = rk[3] ^ rk[shortlen+2];

		if (rk + shortlen + 4 == rko + (4 * (m_nr + 1)))
			break;

		if (len == 24) {
			rk[10] = rk[4] ^ rk[9];
			rk[11] = rk[5] ^ rk[10];
			t = (vector_t)__builtin_ia32_vec_set_v4si(vector4i_t(t), rk[11], 3);
		}
		else if (len == 32) {
			t =(vector_t) __builtin_ia32_vec_set_v4si(vector4i_t(t), rk[11], 3);
			t2 = __builtin_ia32_aeskeygenassist128(t, 0);
			rk[12] = rk[4] ^ __builtin_ia32_vec_ext_v4si(vector4i_t(t2), 2);
			rk[13] = rk[5] ^ rk[12];
			rk[14] = rk[6] ^ rk[13];
			rk[15] = rk[7] ^ rk[14];
			t = (vector_t)__builtin_ia32_vec_set_v4si(vector4i_t(t), rk[15], 3);
		}
		else
			t = (vector_t)__builtin_ia32_vec_set_v4si(vector4i_t(t), rk[7], 3);

	}
}

void drew::AESNI::SetKeyDecrypt(void)
{
	vector_t *rkd = m_rkd;

	memcpy(m_rkd, m_rk, sizeof(m_rkd));

	for (size_t i = 0, j = m_nr; i < j; i++, j--)
		std::swap(rkd[i], rkd[j]);

	for (size_t i = 1; i < m_nr; i++)
		rkd[i] = __builtin_ia32_aesimc128(rkd[i]);
}

int drew::AESNI::Encrypt(uint8_t *out, const uint8_t *in) const
{
	vector_t data;
	memcpy(&data, in, 16);
	data ^= m_rk[0];
	for (size_t i = 1; i < m_nr; i++)
		data = __builtin_ia32_aesenc128(data, m_rk[i]);
	data = __builtin_ia32_aesenclast128(data, m_rk[m_nr]);
	memcpy(out, &data, 16);
	return 0;
}

int drew::AESNI::Decrypt(uint8_t *out, const uint8_t *in) const
{
	vector_t data;
	memcpy(&data, in, 16);
	data ^= m_rkd[0];
	for (size_t i = 1; i < m_nr; i++)
		data = __builtin_ia32_aesdec128(data, m_rkd[i]);
	data = __builtin_ia32_aesdeclast128(data, m_rkd[m_nr]);
	memcpy(out, &data, 16);
	return 0;
}


int drew::AESNI::EncryptFast(FastBlock *bout, const FastBlock *bin,
		size_t n) const
{
	const vector_t *in = (const vector_t *)bin;
	vector_t *out = (vector_t *)bout;
	vector_t x0 = m_rk[0], x1 = m_rk[1], x2 = m_rk[2], x3 = m_rk[3];
	vector_t x4 = m_rk[4], x5 = m_rk[5], x6 = m_rk[6], x7 = m_rk[7];
	vector_t x8 = m_rk[8], x9 = m_rk[9], x10 = m_rk[10], x11 = m_rk[11];
	vector_t x12 = m_rk[12], x13 = m_rk[13], x14 = m_rk[14];

	for (size_t i = 0; i < n; i++, in++, out++) {
		vector_t data;
		data = *in ^ x0;
		data = __builtin_ia32_aesenc128(data, x1);
		data = __builtin_ia32_aesenc128(data, x2);
		data = __builtin_ia32_aesenc128(data, x3);
		data = __builtin_ia32_aesenc128(data, x4);
		data = __builtin_ia32_aesenc128(data, x5);
		data = __builtin_ia32_aesenc128(data, x6);
		data = __builtin_ia32_aesenc128(data, x7);
		data = __builtin_ia32_aesenc128(data, x8);
		data = __builtin_ia32_aesenc128(data, x9);
		if (m_nr == 10)
			data = __builtin_ia32_aesenclast128(data, x10);
		else {
			data = __builtin_ia32_aesenc128(data, x10);
			data = __builtin_ia32_aesenc128(data, x11);
			if (m_nr == 12)
				data = __builtin_ia32_aesenclast128(data, x12);
			else {
				data = __builtin_ia32_aesenc128(data, x12);
				data = __builtin_ia32_aesenc128(data, x13);
				data = __builtin_ia32_aesenclast128(data, x14);
			}
		}
		*out = data;
	}
	return 0;
}

int drew::AESNI::DecryptFast(FastBlock *bout, const FastBlock *bin,
		size_t n) const
{
	const vector_t *in = (const vector_t *)bin;
	vector_t *out = (vector_t *)bout;
	vector_t x0 = m_rkd[0], x1 = m_rkd[1], x2 = m_rkd[2], x3 = m_rkd[3];
	vector_t x4 = m_rkd[4], x5 = m_rkd[5], x6 = m_rkd[6], x7 = m_rkd[7];
	vector_t x8 = m_rkd[8], x9 = m_rkd[9], x10 = m_rkd[10], x11 = m_rkd[11];
	vector_t x12 = m_rkd[12], x13 = m_rkd[13], x14 = m_rkd[14];

	for (size_t i = 0; i < n; i++, in++, out++) {
		vector_t data;
		data = *in ^ x0;
		data = __builtin_ia32_aesdec128(data, x1);
		data = __builtin_ia32_aesdec128(data, x2);
		data = __builtin_ia32_aesdec128(data, x3);
		data = __builtin_ia32_aesdec128(data, x4);
		data = __builtin_ia32_aesdec128(data, x5);
		data = __builtin_ia32_aesdec128(data, x6);
		data = __builtin_ia32_aesdec128(data, x7);
		data = __builtin_ia32_aesdec128(data, x8);
		data = __builtin_ia32_aesdec128(data, x9);
		if (m_nr == 10)
			data = __builtin_ia32_aesdeclast128(data, x10);
		else {
			data = __builtin_ia32_aesdec128(data, x10);
			data = __builtin_ia32_aesdec128(data, x11);
			if (m_nr == 12)
				data = __builtin_ia32_aesdeclast128(data, x12);
			else {
				data = __builtin_ia32_aesdec128(data, x12);
				data = __builtin_ia32_aesdec128(data, x13);
				data = __builtin_ia32_aesdeclast128(data, x14);
			}
		}
		*out = data;
	}
	return 0;
}

const uint8_t drew::AESNI::rcon[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};
#endif
UNHIDE()
