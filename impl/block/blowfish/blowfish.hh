#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "endian.hh"

namespace drew {

class Blowfish
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 8;
		Blowfish();
		~Blowfish() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		inline uint32_t f(uint32_t x);
		void MainAlgorithm(const uint32_t *p, uint32_t &l, uint32_t &r);
		static const uint32_t m_sbox[4 * 256];
		static const uint32_t m_parray[18];
		uint32_t m_s[4 * 256];
		uint32_t m_p[18];
		uint32_t m_pd[18];
};

}

#endif
