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
#ifndef CAST5_HH
#define CAST5_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"
#include "cast.hh"

HIDE()
namespace drew {

class CAST5 : public CAST, public BlockCipher<8, BigEndian>
{
	public:
		CAST5();
		~CAST5() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		void SetUpEndianness();
		void ComputeZSet(uint32_t *z, const uint32_t *x);
		void ComputeXSet(uint32_t *x, const uint32_t *z);
		void ComputeSubkeySetA(uint32_t *sk, const uint32_t *z, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeySetB(uint32_t *sk, const uint32_t *z, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeys(const uint8_t *k);
		uint32_t m_km[16];
		uint8_t m_kr[16];
		bool m_longkey;
};

}
UNHIDE()

#endif
