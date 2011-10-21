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
#ifndef RC2_HH
#define RC2_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class RC2 : public BlockCipher<8, LittleEndian>
{
	public:
		RC2();
		~RC2() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		inline void Mix(uint16_t *r, size_t i, size_t j, size_t s) const;
		inline void MixRound(uint16_t *r, size_t j) const;
		inline void Mash(uint16_t *r, size_t i) const;
		inline void MashRound(uint16_t *r) const;
		inline void RMix(uint16_t *r, size_t i, size_t j, size_t s) const;
		inline void RMixRound(uint16_t *r, size_t j) const;
		inline void RMash(uint16_t *r, size_t i) const;
		inline void RMashRound(uint16_t *r) const;
		uint16_t m_k[64];
		static const uint8_t pitable[];

};
}
UNHIDE()

#endif
