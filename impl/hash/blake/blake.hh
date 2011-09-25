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
#ifndef BLAKE256_HH
#define BLAKE256_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class BLAKE256Transform
{
	public:
		typedef BigEndian endian;
		static void Transform(uint32_t *state, const uint8_t *data,
				const uint32_t *len);
	protected:
		inline static void G(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d,
				int r, int i, const uint32_t *m);
		inline static void Round(uint32_t *v, int r, const uint32_t *m);
};

class BLAKE512Transform
{
	public:
		typedef BigEndian endian;
		static void Transform(uint64_t *state, const uint8_t *data,
				const uint64_t *len);
	protected:
		inline static void G(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d,
				int r, int i, const uint64_t *m);
		inline static void Round(uint64_t *v, int r, const uint64_t *m);
};

template<class T, int Size, int BlkSize, class U>
class BLAKETransform
{
	public:
		typedef BigEndian E;
		static void Transform(T *state, const uint8_t *buf, const T *lenctr)
		{
			return U::Transform(state, buf, lenctr);
		}
		inline static void UpdateCounter(T *lenctr, size_t len)
		{
			const T t = lenctr[0];
			if (unlikely((lenctr[0] += len) < t))
				lenctr[1]++;
		}
		static void Update(T *state, uint8_t *buf, const uint8_t *data,
				size_t len, T *lenctr)
		{
			const T t = lenctr[0];
			const T off = t % BlkSize;
		
			if (off) {
				const size_t i = std::min<size_t>(BlkSize-off, len);
				memcpy(buf+off, data, i);
				UpdateCounter(lenctr, i);
		
				if ((i+off) == BlkSize)
					Transform(state, buf, lenctr);
		
				len -= i;
				data += i;
			}
		
			for (; len >= BlkSize; len -= BlkSize, data += BlkSize) {
				UpdateCounter(lenctr, BlkSize);
				Transform(state, data, lenctr);
			}
			memcpy(buf, data, len);
			UpdateCounter(lenctr, len);
		}
		static void Pad(uint8_t *buf, T *state, const T *lenctr)
		{
			T len[2];
			const T zero[2] = {0, 0};

			const size_t lenoff = lenctr[0];
			const size_t trip = BlkSize - sizeof(len);
			const bool is_big =
				NativeEndian::GetEndianness() == BigEndian::GetEndianness();
			const size_t noff = lenoff % BlkSize;
			size_t off = noff + 1;
			/* Convert bytes to bits. */
			len[!is_big] = (lenctr[1]<<3)|(lenctr[0]>>((sizeof(lenctr[0])*8)-3));
			len[is_big] = lenctr[0]<<3;
		
			/* There is always at least one byte free. */
			buf[noff] = 0x80;
			if (noff >= trip) {
				memset(buf+off, 0, BlkSize-off);
				Transform(state, buf, lenctr);
				off = 0;
			}
			memset(buf+off, 0, trip-off);
			buf[trip-1] |= ((BlkSize / 2) == Size);
			E::Copy(buf+trip, len, sizeof(len), sizeof(len));
			Transform(state, buf, noff && off ? lenctr : zero);
		}
};

class BLAKE256 : public Hash<uint32_t, 32, 64, 64, BigEndian>,
	public BLAKE256Transform
{
	public:
		BLAKE256();
		virtual ~BLAKE256() {}
		void Reset();
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			Update(data, len);
		}
		inline void Update(const uint8_t *data, size_t len)
		{
			BLAKETransform<uint32_t, 32, 64, BLAKE256Transform>::Update(m_hash,
					m_buf, data, len, m_len);
		}
		inline void Pad()
		{
			BLAKETransform<uint32_t, 32, 64, BLAKE256Transform>::Pad(m_buf,
					m_hash, m_len);
		}
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			// do nothing.
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			BLAKE256Transform::Transform(m_hash, data, m_len);
		}
	private:
};

class BLAKE224 : public Hash<uint32_t, 28, 64, 64, BigEndian>,
	public BLAKE256Transform
{
	public:
		BLAKE224();
		virtual ~BLAKE224() {}
		void Reset();
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			Update(data, len);
		}
		inline void Update(const uint8_t *data, size_t len)
		{
			BLAKETransform<uint32_t, 28, 64, BLAKE256Transform>::Update(m_hash,
					m_buf, data, len, m_len);
		}
		inline void Pad()
		{
			BLAKETransform<uint32_t, 28, 64, BLAKE256Transform>::Pad(m_buf,
					m_hash, m_len);
		}
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			// do nothing.
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			BLAKE256Transform::Transform(m_hash, data, m_len);
		}
	private:
};

class BLAKE512 : public Hash<uint64_t, 64, 128, 128, BigEndian>,
	public BLAKE512Transform
{
	public:
		BLAKE512();
		virtual ~BLAKE512() {}
		virtual void Reset();
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			Update(data, len);
		}
		inline void Update(const uint8_t *data, size_t len)
		{
			BLAKETransform<uint64_t, 64, 128, BLAKE512Transform>::Update(m_hash,
					m_buf, data, len, m_len);
		}
		inline void Pad()
		{
			BLAKETransform<uint64_t, 64, 128, BLAKE512Transform>::Pad(m_buf,
					m_hash, m_len);
		}
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			// do nothing.
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			BLAKE512Transform::Transform(m_hash, data, m_len);
		}
	private:
};

class BLAKE384 : public Hash<uint64_t, 48, 128, 128, BigEndian>,
	public BLAKE512Transform
{
	public:
		BLAKE384();
		virtual ~BLAKE384() {}
		void Reset();
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			Update(data, len);
		}
		inline void Update(const uint8_t *data, size_t len)
		{
			BLAKETransform<uint64_t, 48, 128, BLAKE512Transform>::Update(m_hash,
					m_buf, data, len, m_len);
		}
		inline void Pad()
		{
			BLAKETransform<uint64_t, 48, 128, BLAKE512Transform>::Pad(m_buf,
					m_hash, m_len);
		}
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			// do nothing.
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			BLAKE512Transform::Transform(m_hash, data, m_len);
		}
	private:
};

}
UNHIDE()

#endif
