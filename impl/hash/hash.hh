#ifndef HASH_HH
#define HASH_HH

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <functional>
#include <algorithm>

#include <internal.h>

#include "util.hh"

namespace drew {

template<class T, unsigned Size, unsigned BufSize, unsigned BlkSize, class E>
class Hash
{
	public:
		typedef T quantum_t;
		typedef E endian_t;

		static const size_t digest_size = Size;
		static const size_t block_size = BlkSize;
		static const size_t buffer_size = BufSize;

		virtual ~Hash()
		{
			memset(m_len, 0, sizeof(m_len));
			memset(m_buf, 0, sizeof(m_buf));
			memset(m_hash, 0, sizeof(m_hash));
		}
		void Initialize()
		{
			memset(m_len, 0, sizeof(m_len));
			memset(m_buf, 0, sizeof(m_buf));
		}
		virtual void Reset() = 0;
		inline void Update(const uint8_t *data, size_t len)
		{
			const T t = m_len[0];
			const T off = t % BlkSize;
			uint8_t *buf = m_buf;
		
			if ((m_len[0] += len) < t)
				m_len[1]++;

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
		inline void UpdateFast(const uint8_t *data, size_t len)
		{
			const T t = m_len[0];

			if ((m_len[0] += len) < t)
				m_len[1]++;

			len /= BlkSize;

			for (size_t i = 0; i < len; i++, data += BlkSize)
				Transform(data);
		}
		virtual void Pad()
		{
			T len[2];

			const size_t lenoff = m_len[0];
			const size_t trip = BlkSize - sizeof(len);
			const bool is_big =
				NativeEndian::GetEndianness() == BigEndian::GetEndianness();
			const size_t noff = lenoff % BlkSize;
			size_t off = noff + 1;
			uint8_t *buf = m_buf;
			/* Convert bytes to bits. */
			len[!is_big] = (m_len[1]<<3)|(m_len[0]>>((sizeof(m_len[0])*8)-3));
			len[is_big] = m_len[0]<<3;
		
			/* There is always at least one byte free. */
			buf[noff] = 0x80;
			if (noff >= trip) {
				memset(buf+off, 0, BlkSize-off);
				Transform(buf);
				off = 0;
			}
			memset(buf+off, 0, trip-off);
			E::Copy(buf+trip, len, sizeof(len), sizeof(len));
			Transform(buf);
		}
		virtual void GetDigest(uint8_t *digest, bool nopad)
		{
			if (!nopad)
				Pad();

			E::Copy(digest, m_hash, Size);
		}
		virtual size_t GetDigestSize() const
		{
			return Size;
		}
		static inline void Transform(T *, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data) = 0;
		T m_len[2];
		T m_hash[BufSize/sizeof(T)];
		uint8_t m_buf[BlkSize];
	private:
};

}

#endif
