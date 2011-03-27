#ifndef HC256_HH
#define HC256_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class HC256Keystream
{
	public:
		typedef LittleEndian endian_t;
		HC256Keystream();
		~HC256Keystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void GetValue(uint8_t *);
		void Reset();
	protected:
		uint32_t GetValue();
		static inline uint32_t f1(uint32_t x);
		static inline uint32_t f2(uint32_t x);
		inline uint32_t g1(uint32_t x, uint32_t y);
		inline uint32_t g2(uint32_t x, uint32_t y);
		inline uint32_t h1(uint32_t x);
		inline uint32_t h2(uint32_t x);
	private:
		uint32_t m_k[8];
		size_t ctr;
		uint32_t P[1024], Q[1024];
};

class HC256
{
	public:
		HC256();
		~HC256() {}
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		HC256Keystream m_ks;
		uint8_t m_buf[4];
		size_t m_nbytes;
};

}

#endif
