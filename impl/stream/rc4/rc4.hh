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
#ifndef RC4_HH
#define RC4_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

HIDE()
namespace drew {

template<class T>
class RC4Keystream
{
	public:
		typedef T obj_t;
		RC4Keystream() {}
		~RC4Keystream() {}
		void SetKey(const uint8_t *key, size_t sz)
		{
			Reset();
			obj_t j = 0;
			for (size_t i = 0; i < 256; i++) {
				j += s[i] + key[i % sz];
				std::swap(s[i], s[uint8_t(j)]);
			}
		}
		void Reset()
		{
			for (size_t i = 0; i < 256; i++)
				s[i] = i;
			this->i = 0;
			this->j = 0;
		}
		obj_t GetValue()
		{
			i++;
			obj_t &x = s[uint8_t(i)];
			j += x;
			obj_t &y = s[uint8_t(j)];
			std::swap(x, y);
			return s[uint8_t(x + y)];
		}
		void FillBuffer(uint8_t buf[256])
		{
			for (size_t i = 0; i < 256; i++) {
				obj_t &x = s[i];
				j += x;
				obj_t &y = s[uint8_t(j)];
				std::swap(x, y);
				*buf++ = s[uint8_t(x + y)];
			}
		}
		void FillBufferAligned(uint8_t buf[256])
		{
			return FillBuffer(buf);
		}
	protected:
	private:
		obj_t s[256];
		obj_t i, j;

};

class RC4
{
	public:
		RC4();
		RC4(size_t drop);
		~RC4() {}
		inline void SetNonce(const uint8_t *, size_t sz) {}
		void Reset();
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
		void EncryptFast(uint8_t *out, const uint8_t *in, size_t len);
		void DecryptFast(uint8_t *out, const uint8_t *in, size_t len);
		size_t GetKeySize() const
		{
			return m_sz;
		}
	protected:
	private:
		RC4Keystream<int> m_ks;
		size_t m_drop;
		uint8_t m_key[256];
		uint8_t m_buf[256] ALIGNED_T;
		size_t m_nbytes;
		size_t m_sz;
};

}
UNHIDE()

#endif
