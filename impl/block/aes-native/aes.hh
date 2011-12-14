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
/* This implementation supports a variety of i386/amd64-specific native
 * implementations.  Currently supported or planned include Intel's AES-NI and
 * Via's Padlock.
 */
#ifndef AES_NATIVE_HH
#define AES_NATIVE_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

#if defined(__i386__) || defined(__amd64__) || defined(__x86_64__)
#if defined(__GNUC__) && defined(__AES__)
#define FEATURE_AESNI
#endif
#endif
HIDE()
namespace drew {

class AESNative : public BlockCipher<16, BigEndian>
{
	public:
		AESNative() {}
		~AESNative() {};
		virtual int Encrypt(uint8_t *out, const uint8_t *in) const = 0;
		virtual int Decrypt(uint8_t *out, const uint8_t *in) const = 0;
	protected:
		virtual int SetKeyInternal(const uint8_t *key, size_t sz) = 0;
		static const size_t m_nb;
		size_t m_nr, m_nk;
	private:

};

#ifdef FEATURE_AESNI
/* Intel's implementation. */
class AESNI : public AESNative
{
	public:
		typedef long long vector_t __attribute__ ((vector_size (16)));
		typedef int vector4i_t __attribute__ ((vector_size (16)));
		AESNI();
		~AESNI() {};
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
		int EncryptFast(FastBlock *bout, const FastBlock *bin, size_t n) const;
		int DecryptFast(FastBlock *bout, const FastBlock *bin, size_t n) const;
	protected:
		int SetKeyInternal(const uint8_t *key, size_t sz);
		void SetKeyEncrypt(const uint8_t *key, size_t sz);
		void SetKeyDecrypt(void);
		void SetKeyEncrypt128(const uint8_t *key);
		void SetKeyEncrypt192(const uint8_t *key);
		void SetKeyEncrypt256(const uint8_t *key);
		static const uint8_t rcon[];
		vector_t m_rk[16], m_rkd[16];
};
#endif
}
UNHIDE()
#endif
