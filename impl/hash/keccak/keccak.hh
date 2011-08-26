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
#ifndef KECCAK_HH
#define KECCAK_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>


HIDE()
namespace drew {

class Keccak
{
	public:
		typedef uint64_t quantum_t[5];
		typedef LittleEndian endian_t;

		Keccak(size_t);
		virtual ~Keccak()
		{
			memset(m_buf, 0, sizeof(m_buf));
			memset(m_hash, 0, sizeof(m_hash));
		}
		virtual void Reset()
		{
			m_len = 0;
			memset(m_buf, 0, sizeof(m_buf));
			memset(m_hash, 0, sizeof(m_buf));
		}
		inline void Update(const uint8_t *data, size_t len)
		{
			const size_t off = m_len % m_r;
			uint8_t *buf = m_buf;

			m_len += len;
		
			if (off) {
				const size_t i = std::min<size_t>(m_r-off, len);
				memcpy(buf+off, data, i);
		
				if ((i+off) == m_r)
					Transform(buf);
		
				len -= i;
				data += i;
			}
		
			for (; len >= m_r; len -= m_r, data += m_r)
				Transform(data);
			memcpy(buf, data, len);
		}
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			Update(data, len);
		}
		virtual void Pad()
		{
			const size_t noff = m_len % m_r;

			memset(m_buf+noff, 0, m_r-noff);
			m_buf[noff] = 0x01;
			m_buf[m_r-1] |= 0x80;
		
			Transform(m_buf);
		}
		virtual void GetDigest(uint8_t *digest, bool nopad);
		size_t GetDigestSize() const
		{
			return m_c / 2;
		}
		size_t GetBlockSize() const
		{
			return m_r;
		}
		static inline void Transform(uint64_t [5][5], const uint8_t *data);
	protected:
		Keccak() {}
		static inline void Transform(uint64_t [5][5], const uint8_t *data,
				size_t);
		virtual void Transform(const uint8_t *data)
		{
			return Transform(m_hash, data, m_r);
		}
		size_t m_c, m_r;
		size_t m_len;
		uint64_t m_hash[5][5];
		uint8_t m_buf[1152 / 8];
	private:
};

class KeccakWithLimitedNots : public Keccak
{
	public:
		KeccakWithLimitedNots(size_t);
		virtual void Reset();
		static inline void Transform(uint64_t [5][5], const uint8_t *data);
		virtual void GetDigest(uint8_t *digest, bool nopad);
	protected:
		static inline void Transform(uint64_t [5][5], const uint8_t *data,
				size_t);
		virtual void Transform(const uint8_t *data)
		{
			return Transform(m_hash, data, m_r);
		}
	private:
};

}
UNHIDE()

#endif
