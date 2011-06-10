#ifndef ENDIAN_HH
#define ENDIAN_HH

#include <algorithm>
#include "util.h"

#define DREW_BIG_ENDIAN		4321
#define DREW_LITTLE_ENDIAN	1234
#if BYTE_ORDER == BIG_ENDIAN
#define DREW_BYTE_ORDER		DREW_BIG_ENDIAN
#else
#define DREW_BYTE_ORDER		DREW_LITTLE_ENDIAN
#endif

template<class T, size_t N>
struct AlignedBlock
{
	T data[N] ALIGNED_T;
};

inline bool IsAligned(const void *p, size_t mul)
{
	uintptr_t q = reinterpret_cast<uintptr_t>(p);
	return !(q & (mul - 1));
}

template<class T>
inline bool IsAligned(const void *p)
{
#if defined(__GNUC__)
	return IsAligned(p, __alignof__(T));
#else
	return IsAligned(p, sizeof(T));
#endif
}

template<class T>
inline size_t GetNeededAlignment()
{
#if defined(NEEDS_ALIGNMENT) && (NEEDS_ALIGNMENT-0 == 0)
	return 1;
#elif defined(__GNUC__)
	return __alignof__(T);
#else
	return sizeof(T);
#endif
}

template<class T>
inline bool IsSufficientlyAligned(const void *p)
{
	return IsAligned(p, GetNeededAlignment<T>());
}

inline int GetSystemEndianness()
{
	return DREW_BYTE_ORDER;
}

template<class T>
inline T RotateLeft(T x, size_t n)
{
	return (x << n) | (x >> ((sizeof(T)*8) - n));
}

template<class T>
inline T RotateRight(T x, size_t n)
{
	return (x >> n) | (x << ((sizeof(T)*8) - n));
}

// This function copies data from in to out, xoring each byte with the contents
// of mbuf, starting bufrem bytes from the end.  If mbuf runs out of data,
// obj.FillBuffer() is called to add more data.  On return, bufrem contains the
// number of bytes left in mbuf.
template<class T>
inline void CopyAndXor(uint8_t *out, const uint8_t *in, size_t len,
		uint8_t *mbuf, const size_t bufsz, size_t &bufrem, T &obj)
{
	size_t boff = (bufsz - bufrem) % bufsz;
	if (bufrem) {
		const size_t b = std::min(bufrem, len);
		for (size_t i = 0; i < b; i++)
			out[i] = mbuf[boff + i] ^ in[i];
		if ((boff += b) == bufsz)
			boff = 0;
		len -= b;
		out += b;
		in += b;
	}

	while (len >= bufsz) {
		obj.FillBuffer(mbuf);
		for (size_t i = 0; i < bufsz; i++)
			out[i] = mbuf[i] ^ in[i];
		len -= bufsz;
		out += bufsz;
		in += bufsz;
	}

	if (len) {
		obj.FillBuffer(mbuf);
		for (size_t i = 0; i < len; i++)
			out[i] = mbuf[i] ^ in[i];
		boff = len;
	}
	bufrem = (bufsz - boff) % bufsz;
}

template<class T>
inline void XorAligned(T *outp, const T *inp, const T *xorp, size_t len)
{
	return xor_aligned(reinterpret_cast<uint8_t *>(outp),
			reinterpret_cast<const uint8_t *>(inp),
			reinterpret_cast<const uint8_t *>(xorp), len);
}

// This is like CopyAndXor, but we're always working with bufsz-sized chunks.
template<class T>
inline void CopyAndXorAligned(uint8_t *outp, const uint8_t *inp, size_t len,
		uint8_t *mbufp, const size_t bufsz, T &obj)
{
	struct AlignedData {
		uint8_t data[16] ALIGNED_T;
	};

	AlignedData *mbuf = reinterpret_cast<AlignedData *>(mbufp);
	for (size_t i = 0; i < len; i += bufsz) {
		AlignedData *out = reinterpret_cast<AlignedData *>(outp+i);
		const AlignedData *in = reinterpret_cast<const AlignedData *>(inp+i);
		// This strictly may overfill the buffer; nevertheless, we know that
		// there's enough space by the contract of the function.
		obj.FillBufferAligned(mbuf->data);
		XorAligned(out->data, in->data, mbuf->data, bufsz);
	}
}

class EndianBase
{
	public:
		template<class T>
		inline static uint8_t GetByte(T x, size_t n)
		{
			return x >> (n * 8);
		}
		template<class T>
		inline static uint8_t GetByte(const T *p, size_t n)
		{
			return GetByte(*p, n);
		}
		template<class T>
		inline static uint8_t GetArrayByte(const T *p, size_t n)
		{
			return GetByte(p[n/sizeof(T)], (n & (sizeof(T)-1)));
		}
	protected:
		inline static void CopyBackwards(uint8_t *dest, const uint8_t *src,
				size_t len, const size_t sz)
		{
			for (size_t i = 0; i < len; ) {
				const size_t blk = i;
				for (size_t j = 0; i < len && j < sz; j++, i++)
					dest[blk+j] = src[blk+(sz-j-1)];
			}
		}
#if defined(FEATURE_BYTESWAP)
		// Fallback only.
		template<class T>
		inline static void ByteSwap(T &x)
		{
			T p = 0;
			for (size_t i = 0; i < sizeof(T); i++)
				p |= ((x >> (i * 8)) & 0xff) << ((sizeof(T)-i-1) * 8);
			x = p;
		}
#endif
};

// A class to handle converting between endianness in as pleasant a fashion as
// possible.
template<unsigned Endianness>
class Endian : public EndianBase
{
	public:
		// Copy len bytes from src to dest in T-sized chunks.  len is assumed to
		// be a multiple of sizeof(T).
		template<class T>
		inline static uint8_t *Copy(uint8_t *dest, const T *src, size_t len)
		{
			if (DREW_BYTE_ORDER == Endianness) {
				memcpy(dest, src, len);
				return dest;
			}
			else
				return CopyByConvert(dest, src, len);
		}
		template<class T>
		inline static T *Copy(T *dest, const uint8_t *src, size_t len)
		{
			if (DREW_BYTE_ORDER == Endianness) {
				memcpy(dest, src, len);
				return dest;
			}
			else
				return CopyByConvert(dest, src, len);
		}
		// Copy len bytes from src to dest in sz-sized chunks.  When sz ==
		// sizeof(T), the three-argument form should be used instead (for
		// efficiency reasons).
		template<class T>
		inline static uint8_t *Copy(uint8_t *dest, const T *src, size_t len,
				const size_t sz)
		{
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(dest, src, len);
			else
				CopyBackwards(dest, reinterpret_cast<const uint8_t *>(src), len,
						sz);
			return dest;
		}
		template<class T>
		inline static T *Copy(T *dest, const uint8_t *src, size_t len,
				const size_t sz)
		{
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(dest, src, len);
			else
				CopyBackwards(reinterpret_cast<uint8_t *>(dest), src, len, sz);
			return dest;
		}
		// Copy len bytes from src to dest in sz-sized chunks.  No assumptions
		// are made about len with regard to sizeof(T) or sz.
		template<class T>
		inline static uint8_t *CopyCarefully(uint8_t *dest, const T *src, size_t len,
				const size_t sz = sizeof(T))
		{
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(dest, src, len);
			else
				CopyBackwards(dest, reinterpret_cast<const uint8_t *>(src), len,
						sz);
			return dest;
		}
		template<class T>
		inline static T *CopyCarefully(T *dest, const uint8_t *src, size_t len,
				const size_t sz = sizeof(T))
		{
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(dest, src, len);
			else
				CopyBackwards(reinterpret_cast<uint8_t *>(dest), src, len, sz);
			return dest;
		}
		// Return a pointer to the existing buffer if possible; otherwise call
		// the three-argument form of Copy.
		template<class T>
		inline static const T *CopyIfNeeded(T *buf, const uint8_t *p,
				size_t len)
		{
			if (GetEndianness() == GetSystemEndianness() && 
					IsSufficientlyAligned<T>(p))
				return reinterpret_cast<const T *>(p);
			else
				return Copy(buf, p, len);
		}
		// Build a T out of bytes and return it.
		template<class T>
		inline static T Convert(const uint8_t *p)
		{
			T x;
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(&x, p, sizeof(x));
			else {
#if defined(FEATURE_BYTESWAP)
				memcpy(&x, p, sizeof(x));
				ByteSwap(x);
#else
				Copy(&x, p, sizeof(x), sizeof(x));
#endif
			}
			return x;
		}
		// Store a T into a byte buffer.
		template<class T>
		inline static void Convert(uint8_t *buf, T p)
		{
			if (DREW_BYTE_ORDER == Endianness)
				memcpy(buf, &p, sizeof(p));
			else {
#if defined(FEATURE_BYTESWAP)
				ByteSwap(p);
				memcpy(buf, &p, sizeof(p));
#else
				Copy(buf, &p, sizeof(p), sizeof(p));
#endif
			}
		}
		// Return a constant representing the endianness.
		inline static int GetEndianness()
		{
			return Endianness;
		}
	protected:
		// Same contract as Copy.  Internal implementation function.
		template<class T>
		inline static uint8_t *CopyByConvert(uint8_t *dest, const T *src, size_t len)
		{
			for (size_t i = 0, j = 0; j < len; i++, j += sizeof(T))
				Convert(dest+j, src[i]);
			return dest;
		}
		template<class T>
		inline static T *CopyByConvert(T *dest, const uint8_t *src, size_t len)
		{
			for (size_t i = 0, j = 0; j < len; i++, j += sizeof(T))
				dest[i] = Convert<T>(src+j);
			return dest;
		}
};

#ifdef FEATURE_BYTESWAP
template<>
inline void EndianBase::ByteSwap(uint16_t &x)
{
	x = 
#if defined(FEATURE_BYTESWAP_GNU)
		bswap_16(x);
#elif defined(FEATURE_BYTESWAP_BSD)
		bswap16(x);
#elif defined(FEATURE_BYTESWAP_OPENBSD)
		swap16(x);
#endif
}

template<>
inline void EndianBase::ByteSwap(uint32_t &x)
{
	x = 
#if defined(FEATURE_BYTESWAP_GNU)
		bswap_32(x);
#elif defined(FEATURE_BYTESWAP_BSD)
		bswap32(x);
#elif defined(FEATURE_BYTESWAP_OPENBSD)
		swap32(x);
#endif
}

template<>
inline void EndianBase::ByteSwap(uint64_t &x)
{
	x = 
#if defined(FEATURE_BYTESWAP_GNU)
		bswap_64(x);
#elif defined(FEATURE_BYTESWAP_BSD)
		bswap64(x);
#elif defined(FEATURE_BYTESWAP_OPENBSD)
		swap64(x);
#endif
}
#endif

class LittleEndian : public Endian<DREW_LITTLE_ENDIAN>
{
};

class BigEndian : public Endian<DREW_BIG_ENDIAN>
{
	public:
		template<class T>
		inline static T Convert(const uint8_t *p)
		{
			return Endian<DREW_BIG_ENDIAN>::Convert<T>(p);
		}
		template<class T>
		inline static void Convert(uint8_t *buf, T p)
		{
			return Endian<DREW_BIG_ENDIAN>::Convert<T>(buf, p);
		}
};

// For algorithms which are completely byte-order agnostic.
class NonEndian : public EndianBase
{
	public:
		inline static uint8_t *CopyCarefully(uint8_t *dest, const uint8_t *src,
				size_t len, const size_t sz = 1)
		{
			memcpy(dest, src, len);
			return dest;
		}
		inline static uint8_t *Copy(uint8_t *dest, const uint8_t *src,
				size_t len, const size_t sz)
		{
			memcpy(dest, src, len);
			return dest;
		}
		inline static uint8_t *Copy(uint8_t *dest, const uint8_t *src,
				size_t len)
		{
			memcpy(dest, src, len);
			return dest;
		}
		inline static int GetEndianness()
		{
			return 0;
		}
};

template<>
inline uint32_t BigEndian::Convert(const uint8_t *p)
{
	uint32_t x;
	memcpy(&x, p, sizeof(x));
	return htonl(x);
}
template<>
inline uint16_t BigEndian::Convert(const uint8_t *p)
{
	uint16_t x;
	memcpy(&x, p, sizeof(x));
	return htons(x);
}

template<>
inline void BigEndian::Convert(uint8_t *buf, uint32_t p)
{
	uint32_t x = ntohl(p);
	memcpy(buf, &x, sizeof(x));
}
template<>
inline void BigEndian::Convert(uint8_t *buf, uint16_t p)
{
	uint16_t x = ntohs(p);
	memcpy(buf, &x, sizeof(x));
}

#if BYTE_ORDER == BIG_ENDIAN
typedef BigEndian NativeEndian;
#else
typedef LittleEndian NativeEndian;
#endif

#endif
