#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class Twofish : public BlockCipher<16>
{
	public:
		typedef LittleEndian endian_t;
		Twofish();
		~Twofish() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		inline uint32_t Mod(uint32_t) const;
		inline uint32_t ReedSolomon(uint32_t, uint32_t) const;
		inline uint32_t h0(uint32_t, const uint32_t *, size_t) const;
		inline uint32_t h(uint32_t, const uint32_t *, size_t) const;
		inline void f(const uint32_t *, uint32_t, uint32_t, uint32_t &,
				uint32_t &) const;
		inline void finv(const uint32_t *, uint32_t, uint32_t, uint32_t &,
				uint32_t &) const;
		inline uint32_t g0(uint32_t) const;
		inline uint32_t g1(uint32_t) const;
	private:
		static const uint8_t q0[256], q1[256];
		static const uint32_t mds[4][256];
		uint32_t m_s[4][256];
		uint32_t m_k[40];
};

}

#endif
