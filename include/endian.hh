#ifndef ENDIAN_HH
#define ENDIAN_HH

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

class BigEndian
{
	public:
		template<class T>
		void operator()(uint8_t *dest, const T *src, size_t len,
				const size_t sz = sizeof(T))
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t *p = dest;
			size_t i, j;
			for (i = 0; i < len; i += sz)
				for (j = 0; j < sz/2; j++)
					std::swap(p[i+j], p[i+(sz-j-1)]);
#endif
		}
		template<class T>
		void operator()(T *dest, const uint8_t *src, size_t len,
				const size_t sz = sizeof(T))
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t *p = reinterpret_cast<uint8_t *>(dest);
			size_t i, j;
			for (i = 0; i < len; i += sz)
				for (j = 0; j < sz/2; j++)
					std::swap(p[i+j], p[i+(sz-j-1)]);
#endif
		}
	protected:
	private:
};

class LittleEndian
{
	public:
		template<class T>
		void operator()(uint8_t *dest, const T *src, size_t len,
				const size_t sz = sizeof(T))
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == BIG_ENDIAN
			uint8_t *p = dest;
			size_t i, j;
			for (i = 0; i < len; i += sz)
				for (j = 0; j < sz/2; j++)
					std::swap(p[i+j], p[i+(sz-j-1)]);
#endif
		}
		template<class T>
		void operator()(T *dest, const uint8_t *src, size_t len,
				const size_t sz = sizeof(T))
		{
			memcpy(dest, src, len);
#if BYTE_ORDER == BIG_ENDIAN
			uint8_t *p = reinterpret_cast<uint8_t *>(dest);
			size_t i, j;
			for (i = 0; i < len; i += sz) 
				for (j = 0; j < sz/2; j++)
					std::swap(p[i+j], p[i+(sz-j-1)]);
#endif
		}
	protected:
	private:
};

#endif
