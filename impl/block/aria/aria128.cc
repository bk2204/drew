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
#define ARIA_128
#include "aria.hh"

HIDE()
extern "C" {
#if defined(FEATURE_128_BIT_INTEGERS)
	PLUGIN_STRUCTURE(aria, ARIA128)
#endif
	PLUGIN_DATA_START()
#if defined(FEATURE_128_BIT_INTEGERS)
	PLUGIN_DATA(aria, "ARIA")
#endif
	PLUGIN_DATA_END()

#if defined(FEATURE_128_BIT_INTEGERS)
static int ariatest(void *, const drew_loader_t *)
{
	using namespace drew;
	return test<ARIA128>(NULL, NULL);
}
#endif

EXPORT()
int DREW_PLUGIN_NAME(aria128)(void *ldr, int op, int id, void *p) 
{ 
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]); 
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

#if defined(FEATURE_128_BIT_INTEGERS)
typedef drew::ARIA128::endian_t E;

drew::ARIA128::uint128_t drew::ARIA128::fo128(uint128_t a, uint128_t b) const
{
	AlignedData abuf, bbuf, cbuf, t;
	uint128_t c;

	E::Copy(t.data, &a, sizeof(t));
	Permute(abuf.data, t.data);
	E::Copy(t.data, &b, sizeof(t));
	Permute(bbuf.data, t.data);
	fo(cbuf, abuf, bbuf);
	Permute(t.data, cbuf.data);
	E::Copy(&c, t.data, sizeof(t));
	return c;
}

drew::ARIA128::uint128_t drew::ARIA128::fe128(uint128_t a, uint128_t b) const
{
	AlignedData abuf, bbuf, cbuf, t;
	uint128_t c;

	E::Copy(t.data, &a, sizeof(t));
	Permute(abuf.data, t.data);
	E::Copy(t.data, &b, sizeof(t));
	Permute(bbuf.data, t.data);
	fe(cbuf, abuf, bbuf);
	Permute(t.data, cbuf.data);
	E::Copy(&c, t.data, sizeof(t));
	return c;
}

int drew::ARIA128::SetKeyInternal(const uint8_t *key, size_t len)
{
	// There are only three constants, but they're repeated for convenience.
	static const uint128_t c[5] = {
		((uint128_t(0x517cc1b727220a94) << 64) | 0xfe13abe8fa9a6ee0),
		((uint128_t(0x6db14acc9e21c820) << 64) | 0xff28b1d5ef5de2b0),
		((uint128_t(0xdb92371d2126e970) << 64) | 0x0324977504e8c90e),
		((uint128_t(0x517cc1b727220a94) << 64) | 0xfe13abe8fa9a6ee0),
		((uint128_t(0x6db14acc9e21c820) << 64) | 0xff28b1d5ef5de2b0)
	};
	uint8_t buf[32] = {0};

	memcpy(buf, key, len);
	uint128_t kl, kr;

	E::Copy(&kl, buf+ 0, sizeof(kl));
	E::Copy(&kr, buf+16, sizeof(kr));

	size_t nrounds;

	switch (len / 8) {
		case 2:
			m_off = 0;
			nrounds = 12;
			break;
		case 3:
			m_off = 1;
			nrounds = 14;
			break;
		case 4:
			m_off = 2;
			nrounds = 16;
			break;
		default:
			return -DREW_ERR_INVALID;
	}

	const uint128_t *ck = c + m_off;
	uint128_t w[4];
	w[0] = kl;
	w[1] = fo128(w[0], ck[0]) ^ kr;
	w[2] = fe128(w[1], ck[1]) ^ w[0];
	w[3] = fo128(w[2], ck[2]) ^ w[1];

	uint128_t ek[17];
	static const size_t offsets[] = {19, 31, 67, 97};
	for (size_t i = 0, j = 0; i < 16; i += 4, j++) {
		ek[i + 0] = w[0] ^ RotateRight(w[1], offsets[j]);
		ek[i + 1] = w[1] ^ RotateRight(w[2], offsets[j]);
		ek[i + 2] = w[2] ^ RotateRight(w[3], offsets[j]);
		ek[i + 3] = w[3] ^ RotateRight(w[0], offsets[j]);
	}
	ek[16] = w[0] ^ RotateLeft(w[1], 19);

	for (size_t i = 0; i < 17; i++) {
		AlignedData d;
		E::Copy(d.data, &ek[i], 16);
		Permute(m_ek[i].data, d.data);
	}

	memcpy(m_dk[0].data, m_ek[nrounds].data, 16);
	for (size_t i = 1; i < nrounds; i++)
		afunc(m_dk[i], m_ek[nrounds - i]);
	memcpy(m_dk[nrounds].data, m_ek[0].data, 16);

	return 0;
}
#endif
UNHIDE()
