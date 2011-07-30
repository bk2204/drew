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
#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class Twofish : public BlockCipher<16>
{
	public:
		typedef LittleEndian endian_t;
		Twofish();
		~Twofish() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		inline uint32_t Mod(uint32_t) const;
		inline uint32_t ReedSolomon(uint32_t, uint32_t) const;
		inline uint32_t h0(uint32_t, const uint32_t *, size_t) const;
		inline uint32_t h(uint32_t, const uint32_t *, size_t) const;
		inline void f(const uint32_t *, uint32_t, uint32_t, uint32_t &,
				uint32_t &) const;
		inline void finv(const uint32_t *, uint32_t, uint32_t, uint32_t &,
				uint32_t &) const;
		inline uint32_t g0(uint32_t) const;
		inline uint32_t g1(uint32_t) const;
	private:
		static const uint8_t q0[256], q1[256];
		static const uint32_t mds[4][256];
		uint32_t m_s[4][256];
		uint32_t m_k[40];
};

}
UNHIDE()

#endif
