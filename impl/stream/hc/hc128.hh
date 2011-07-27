#ifndef HC128_HH
#define HC128_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

HIDE()
namespace drew {

class HC128Keystream
{
	public:
		typedef LittleEndian endian_t;
		HC128Keystream();
		~HC128Keystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void FillBuffer(uint8_t *);
		void Reset();
	protected:
		static inline uint32_t f1(uint32_t x);
		static inline uint32_t f2(uint32_t x);
		static inline uint32_t g1(uint32_t x, uint32_t y, uint32_t z);
		static inline uint32_t g2(uint32_t x, uint32_t y, uint32_t z);
		inline uint32_t h1(uint32_t x);
		inline uint32_t h2(uint32_t x);
	private:
		uint32_t m_k[4];
		size_t ctr;
		uint32_t P[512], Q[512];
};

class HC128
{
	public:
		HC128();
		~HC128() {}
		void Reset();
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		HC128Keystream m_ks;
		uint8_t m_iv[16];
		uint8_t m_buf[4096];
		size_t m_nbytes;
};

}
UNHIDE()

#endif
