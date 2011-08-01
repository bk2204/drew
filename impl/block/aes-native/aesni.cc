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

int drew::AESNI::SetKey(const uint8_t *key, size_t len)
{
	switch (len) {
		case 16:
			SetKeyEncrypt128(key);
			break;
		case 24:
			SetKeyEncrypt192(key);
			break;
		case 32:
			SetKeyEncrypt256(key);
			break;
		case 20:
		case 28:
			return -DREW_ERR_NOT_IMPL;
		default:
			return -DREW_ERR_INVALID;
	}
	m_nk = (len / 4);
	m_nr = 6 + std::max(m_nb, m_nk);

	SetKeyDecrypt();
	return 0;
}

typedef drew::AESNI::vector_t vector_t;
typedef drew::AESNI::vector4i_t vector4i_t;

/* This basic idea is from the Intel documentation.  It has been converted into
 * GCC intrinsics using GCC vectorization.
 */
static inline vector_t Assist128(vector_t t1, vector_t t2)
{
	vector_t t3;
	t2 = (vector_t)__builtin_ia32_pshufd(vector4i_t(t2), 0xff);
	t3 = __builtin_ia32_pslldqi128(t1, 32);
	t1 ^= t3;
	t3 = __builtin_ia32_pslldqi128(t3, 32);
	t1 ^= t3;
	t3 = __builtin_ia32_pslldqi128(t3, 32);
	t1 ^= t3;
	t1 ^= t2;
	return t1;
}

void drew::AESNI::SetKeyEncrypt128(const uint8_t *key)
{
	vector_t t1, t2;
	memcpy(&t1, key, 16);
	for (size_t i = 0; i < 10; i++) {
		m_rk[i] = t1;
		t2 = __builtin_ia32_aeskeygenassist128(t1, rcon[i]);
		t1 = Assist128(t1, t2);
	}
	m_rk[10] = t1;
}

static inline void Assist192(vector_t &t1, vector_t &t2, vector_t &t3)
{
	vector_t t4;
	t2 = (vector_t)__builtin_ia32_pshufd(vector4i_t(t2), 0x55);
	t4 = __builtin_ia32_pslldqi128(t1, 32);
	t1 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t1 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t1 ^= t4;
	t1 ^= t2;
	t2 = (vector_t)__builtin_ia32_pshufd(vector4i_t(t1), 0xff);
	t4 = __builtin_ia32_pslldqi128(t3, 32);
	t3 ^= t4;
	t3 ^= t2;
}

void drew::AESNI::SetKeyEncrypt192(const uint8_t *key)
{
	typedef double vector2d_t __attribute__((vector_size(16)));
	uint8_t buf[32] ALIGNED_T = {0x00};
	vector_t t1, t2, t3;
	memcpy(buf, key, 24);
	memcpy(&t1, buf, 16);
	memcpy(&t3, buf+16, 16);
	for (size_t i = 0, ri = 1; i < 12; i += 3) {
		vector_t t5 = t3;
		m_rk[i+0] = t1;
		t2 = __builtin_ia32_aeskeygenassist128(t3, ri);
		ri <<= 1;
		Assist192(t1, t2, t3);
		m_rk[i+1] = (vector_t)__builtin_ia32_shufpd(vector2d_t(t5),
				vector2d_t(t1), 0);
		m_rk[i+2] = (vector_t)__builtin_ia32_shufpd(vector2d_t(t1),
				vector2d_t(t3), 1);
		t2 = __builtin_ia32_aeskeygenassist128(t3, ri);
		ri <<= 1;
		Assist192(t1, t2, t3);
	}
	m_rk[12] = t1;
	m_rk[13] = t3;
}

static inline void Assist256(vector_t &t1, vector_t &t2)
{
	vector_t t4;
	t2 = (vector_t)__builtin_ia32_pshufd(vector4i_t(t2), 0xff);
	t4 = __builtin_ia32_pslldqi128(t1, 32);
	t1 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t1 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t1 ^= t4;
	t1 ^= t2;
}

static inline void AssistMore256(vector_t &t1, vector_t &t3)
{
	vector_t t2, t4;
	t4 = __builtin_ia32_aeskeygenassist128(t1, 0);
	t2 = (vector_t)__builtin_ia32_pshufd(vector4i_t(t4), 0xaa);
	t4 = __builtin_ia32_pslldqi128(t3, 32);
	t3 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t3 ^= t4;
	t4 = __builtin_ia32_pslldqi128(t4, 32);
	t3 ^= t4;
	t3 ^= t2;
}

void drew::AESNI::SetKeyEncrypt256(const uint8_t *key)
{
	vector_t t1, t2, t3;
	memcpy(&t1, key, 16);
	memcpy(&t3, key+16, 16);
	m_rk[0] = t1;
	m_rk[1] = t3;
	for (size_t i = 2, ri = 1; i < 14; i += 2) {
		t2 = __builtin_ia32_aeskeygenassist128(t3, ri);
		ri <<= 1;
		Assist256(t1, t2);
		m_rk[i+0] = t1;
		AssistMore256(t1, t3);
		m_rk[i+1] = t3;
	}
	t2 = __builtin_ia32_aeskeygenassist128(t3, 0x40);
	Assist256(t1, t2);
	m_rk[14] = t1;
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

const uint8_t drew::AESNI::rcon[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};
#endif
UNHIDE()
