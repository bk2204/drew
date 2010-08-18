#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "endian.hh"

namespace drew {

class Twofish
{
	public:
		typedef LittleEndian endian_t;
		static const size_t block_size = 16;
		Twofish();
		~Twofish() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
		inline uint32_t Mod(uint32_t);
		inline uint32_t ReedSolomon(uint32_t, uint32_t);
		inline uint32_t h0(uint32_t, const uint32_t *, size_t);
		inline uint32_t h(uint32_t, const uint32_t *, size_t);
		inline void f(const uint32_t *, uint32_t, uint32_t, uint32_t &,
				uint32_t &);
		inline void finv(size_t, uint32_t, uint32_t, uint32_t &, uint32_t &);
		inline uint32_t g(uint32_t);
	private:
		static const uint8_t q0[256], q1[256];
		static const uint32_t mds[4][256];
		uint32_t m_s[4][256];
		uint32_t m_k[40];
};

}

#endif
