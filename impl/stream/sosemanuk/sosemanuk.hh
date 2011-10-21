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
#ifndef SOSEMANUK_HH
#define SOSEMANUK_HH

#include <stddef.h>
#include <stdint.h>

#define BLOCK_NO_MACROS
#include "../../block/serpent/serpent.hh"
#include "util.hh"

HIDE()
namespace drew {

class SosemanukKeystream
{
	public:
		typedef LittleEndian endian_t;
		SosemanukKeystream();
		~SosemanukKeystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void FillBuffer(uint8_t *);
		void Reset();
	protected:
	private:
		Serpent m_serpent;
		uint32_t m_s[50], m_r1, m_r2;
		static const uint32_t tablea[], tableainv[];
};

class Sosemanuk
{
	public:
		Sosemanuk();
		~Sosemanuk() {}
		void Reset();
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		SosemanukKeystream m_ks;
		uint8_t m_k[32];
		uint8_t m_iv[16];
		uint8_t m_buf[160] ALIGNED_T;
		size_t m_keysz;
		size_t m_nbytes;
};

}
UNHIDE()

#endif
