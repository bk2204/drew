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
#ifndef CAMELLIA_HH
#define CAMELLIA_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class Camellia : public BlockCipher<16, BigEndian>
{
	public:
		Camellia();
		~Camellia() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		void SetKey128(uint64_t k[4]);
		void SetKey192(uint64_t k[4]);
		void SetKey256(uint64_t k[4]);
		void Encrypt128(uint64_t d[2]) const;
		void Encrypt256(uint64_t d[2]) const;
		void Decrypt128(uint64_t d[2]) const;
		void Decrypt256(uint64_t d[2]) const;
		inline void EncryptPair(uint64_t &, uint64_t &, unsigned) const;
		inline void DecryptPair(uint64_t &, uint64_t &, unsigned) const;
		uint64_t f(uint64_t x, uint64_t k) const;
		uint64_t fl(uint64_t x, uint64_t k) const;
		uint64_t flinv(uint64_t y, uint64_t k) const;
		uint64_t spfunc(uint64_t x) const;
		uint64_t kw[4];
		uint64_t ku[24];
		uint64_t kl[6];
		void (Camellia::*fenc)(uint64_t d[2]) const;
		void (Camellia::*fdec)(uint64_t d[2]) const;
		static const uint64_t s[8][256];
	private:
};

}
UNHIDE()

#endif
