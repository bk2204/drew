#ifndef HASH_HH
#define HASH_HH

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <functional>
#include <algorithm>

#include <internal.h>

#include "endian.hh"

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

		virtual ~Hash() {}
		virtual void Initialize()
		{
			memset(m_len, 0, sizeof(m_len));
			memset(m_buf, 0, sizeof(m_buf));
			memset(&m_off, 0, sizeof(m_off));
		}
		virtual void Update(const uint8_t *data, size_t len)
		{
			const T blklen = BlkSize;
			const T blkmask = (blklen-1);
			const T t = m_len[0];
			const T off = t & blkmask;
			const size_t i = std::min<size_t>(blklen-off, len);
			uint8_t *buf = m_buf;
		
			if ((m_len[0] += len) < t)
				m_len[1]++;
		
			memcpy(buf+off, data, i);
		
			if ((i+off) == blklen)
				Transform(buf);
		
			len-=i;
			data+=i;
		
			for (; len >= blklen; len -= blklen, data += blklen)
				Transform(data);
			memcpy(buf, data, len);
		}
		virtual void Pad()
		{
			const size_t blklen = BlkSize;
			const size_t lenoff = m_len[0];
			uint8_t inplen[sizeof(T)*2];
			const size_t lensz = sizeof(inplen);
			const size_t trip = blklen-lensz;
			size_t off = lenoff & (blklen-1);
			uint8_t *buf = m_buf;
			T len[2];
			E e;
			/* Convert bytes to bits. */
			len[1] = (m_len[1]<<3)|(m_len[0]>>((sizeof(m_len[0])*8)-3));
			len[0] = m_len[0]<<3;
			e(inplen, len, sizeof(len), sizeof(len));
		
			/* There is always at least one byte free. */
			buf[off] = 0x80;
			off++;
			if ((off-1) >= trip) {
				memset(buf+off, 0, blklen-off);
				Transform(buf);
				off = 0;
			}
			memset(buf+off, 0, trip-off);
			memcpy(buf+trip, inplen, lensz);
			Transform(buf);
		}
		virtual void GetDigest(uint8_t *digest)
		{
			Pad();

			E e;
			e(digest, m_hash, Size);
		}
		static void Transform(T *, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data) = 0;
		T m_len[2];
		T m_hash[BufSize/sizeof(T)];
		uint8_t m_buf[BlkSize];
		size_t m_off;
	private:
};

}

#endif
