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
#ifndef GROESTL_HH
#define GROESTL_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class Gr\u00f8stlImplementation
{
	public:
		virtual void GetDigest(uint8_t *digest, bool nopad) = 0;
		virtual size_t GetBlockSize() const = 0;
		virtual size_t GetBufferSize() const = 0;
		virtual ~Gr\u00f8stlImplementation()
		{
			memset(m_buf, 0, sizeof(m_buf));
			memset(m_hash, 0, sizeof(m_hash));
		}
		void Initialize()
		{
			memset(m_buf, 0, sizeof(m_buf));
			m_off = 0;
		}
		virtual void Reset() = 0;
		inline void Update(const uint8_t *data, size_t len)
		{
			const size_t BlkSize = GetBlockSize();
			const uint64_t off = m_off & (BlkSize-1);
			uint8_t *buf = m_buf;
	
			m_off += len;

			if (off) {
				const size_t i = std::min<size_t>(BlkSize-off, len);
				memcpy(buf+off, data, i);
		
				if ((i+off) == BlkSize)
					Transform(buf);
		
				len-=i;
				data+=i;
			}
		
			for (; len >= BlkSize; len -= BlkSize, data += BlkSize)
				Transform(data);
			memcpy(buf, data, len);
		}
		inline void Pad()
		{
			const size_t BlkSize = GetBlockSize();
			const size_t trip = BlkSize - sizeof(m_nblocks);
			const size_t noff = m_off & (BlkSize-1);
			size_t off = noff + 1;
			uint8_t *buf = m_buf;
		
			/* There is always at least one byte free. */
			buf[noff] = 0x80;
			if (noff >= trip) {
				memset(buf+off, 0, BlkSize-off);
				Transform(buf);
				off = 0;
			}
			memset(buf+off, 0, trip-off);
			m_nblocks++;
			BigEndian::Copy(buf+trip, &m_nblocks, sizeof(m_nblocks));
			Transform(buf);
		}
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			const size_t BlkSize = GetBlockSize();
			len /= BlkSize;

			for (size_t i = 0; i < len; i++, data += BlkSize)
				Transform(data);
		}
		size_t GetDigestSize() const
		{
			return m_size;
		}
	protected:
		uint64_t m_hash[16] ALIGNED_T;
		uint8_t m_buf[1024/8];
		uint64_t m_nblocks;
		size_t m_size;
		size_t m_off;
		virtual void Transform(const uint8_t *data) = 0;
};

class Gr\u00f8stl256 : public Gr\u00f8stlImplementation
{
	public:
		Gr\u00f8stl256(size_t sz);
		virtual ~Gr\u00f8stl256() {}
		void Reset();
		void GetDigest(uint8_t *digest, bool nopad);
		size_t GetBlockSize() const
		{
			return 512 / 8;
		}
		size_t GetBufferSize() const
		{
			return 512 / 8;
		}
		static void Transform(uint64_t *state, const uint8_t *data);
	protected:
		static void ComputeP(uint64_t *, uint64_t *, uint64_t);
		static void ComputeQ(uint64_t *, uint64_t *, uint64_t);
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
			m_nblocks++;
		}
	private:
};

class Gr\u00f8stl512: public Gr\u00f8stlImplementation
{
	public:
		Gr\u00f8stl512(size_t sz);
		virtual ~Gr\u00f8stl512() {}
		void Reset();
		void GetDigest(uint8_t *digest, bool nopad);
		size_t GetBlockSize() const
		{
			return 1024 / 8;
		}
		size_t GetBufferSize() const
		{
			return 1024 / 8;
		}
		static void Transform(uint64_t *state, const uint8_t *data);
	protected:
		static void ComputeP(uint64_t *, uint64_t *, uint64_t);
		static void ComputeQ(uint64_t *, uint64_t *, uint64_t);
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
			m_nblocks++;
		}
	private:
};

class Gr\u00f8stl
{
	public:
		typedef uint64_t quantum_t;
		Gr\u00f8stl(size_t sz)
		{
			m_impl = 0;
			if (sz <= (256 / 8))
				m_impl = new Gr\u00f8stl256(sz);
			else
				m_impl = new Gr\u00f8stl512(sz);
		}
		virtual ~Gr\u00f8stl()
		{
			delete m_impl;
		}
		void Reset()
		{
			m_impl->Reset();
		}
		void GetDigest(uint8_t *digest, bool nopad)
		{
			m_impl->GetDigest(digest, nopad);
		}
		size_t GetDigestSize() const
		{
			return m_impl->GetDigestSize();
		}
		size_t GetBlockSize() const
		{
			return m_impl->GetBlockSize();
		}
		size_t GetBufferSize() const
		{
			return m_impl->GetBufferSize();
		}
		void Initialize()
		{
			return m_impl->Initialize();
		}
		void Update(const uint8_t *data, size_t len)
		{
			return m_impl->Update(data, len);
		}
		void Pad()
		{
			return m_impl->Pad();
		}
		void UpdateFast(const uint8_t *data, size_t len)
		{
			return m_impl->UpdateFast(data, len);
		}
		static void Transform(uint64_t *state, const uint8_t *data);
	protected:
	private:
		Gr\u00f8stlImplementation *m_impl;
};
}
UNHIDE()

#endif
