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
#ifndef SEED_HH
#define SEED_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class SEED : public BlockCipher<16, BigEndian>
{
	public:
		SEED();
		~SEED() {};
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		int SetKeyInternal(const uint8_t *key, size_t sz);
		static inline uint64_t GenerateSubkey(uint32_t k[4], uint32_t kci);
		static inline uint64_t OddKey(uint32_t k[4], uint32_t kci);
		static inline uint64_t EvenKey(uint32_t k[4], uint32_t kci);
		static inline uint64_t f(uint64_t k, uint64_t r);
		static inline uint32_t g(uint32_t x);
		static const uint32_t ss0[], ss1[], ss2[], ss3[];
	private:
		uint64_t m_k[16];

};
}
UNHIDE()

#endif
