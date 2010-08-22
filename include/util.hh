#ifndef ENDIAN_HH
#define ENDIAN_HH

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

class Endian
{
	public:
		inline static void InplaceSwap(uint8_t *dest, size_t len, size_t sz)
		{
			uint8_t *p = dest;
			size_t i, j;
			for (i = 0; i < len; i += sz)
				for (j = 0; j < sz/2; j++)
					std::swap(p[i+j], p[i+(sz-j-1)]);
		}
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
};

class BigEndian : public Endian
{
	public:
		template<class T>
		static void Copy(uint8_t *dest, const T *src, size_t len)
		{
			Copy(dest, src, len, sizeof(T));
		}
		template<class T>
		static void Copy(T *dest, const uint8_t *src, size_t len)
		{
			Copy(dest, src, len, sizeof(T));
		}
		template<class T>
		static void Copy(uint8_t *dest, const T *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == LITTLE_ENDIAN
			InplaceSwap(dest, len, sz);
#endif
		}
		template<class T>
		static void Copy(T *dest, const uint8_t *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == LITTLE_ENDIAN
			InplaceSwap(reinterpret_cast<uint8_t *>(dest), len, sz);
#endif
		}
		inline static void Copy(uint8_t *dest, const uint8_t *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
		}
		inline static void Copy(uint8_t *dest, const uint8_t *src, size_t len)
		{
			memcpy(dest, src, len);
		}
		inline static int GetEndianness()
		{
			return 4321;
		}
	protected:
	private:
};

class LittleEndian : public Endian
{
	public:
		template<class T>
		static void Copy(uint8_t *dest, const T *src, size_t len)
		{
			Copy(dest, src, len, sizeof(T));
		}
		template<class T>
		static void Copy(T *dest, const uint8_t *src, size_t len)
		{
			Copy(dest, src, len, sizeof(T));
		}
		template<class T>
		static void Copy(uint8_t *dest, const T *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == BIG_ENDIAN
			InplaceSwap(dest, len, sz);
#endif
		}
		template<class T>
		static void Copy(T *dest, const uint8_t *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == BIG_ENDIAN
			InplaceSwap(reinterpret_cast<uint8_t *>(dest), len, sz);
#endif
		}
		inline static void Copy(uint8_t *dest, const uint8_t *src, size_t len,
				const size_t sz)
		{
			memcpy(dest, src, len);
		}
		inline static void Copy(uint8_t *dest, const uint8_t *src, size_t len)
		{
			memcpy(dest, src, len);
		}
		inline static int GetEndianness()
		{
			return 1234;
		}
	protected:
	private:
};

#if BYTE_ORDER == BIG_ENDIAN
typedef BigEndian NativeEndian;
#else
typedef LittleEndian NativeEndian;
#endif

#endif
