#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class Blowfish : public BlockCipher<8>
{
	public:
		typedef BigEndian endian_t;
		Blowfish();
		~Blowfish() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		inline uint32_t f(uint32_t x) const;
		void MainAlgorithm(const uint32_t *p, uint32_t d[2]) const;
		static const uint32_t m_sbox[4 * 256];
		static const uint32_t m_parray[18];
		uint32_t m_s[4 * 256];
		uint32_t m_p[18];
		uint32_t m_pd[18];
};

}
UNHIDE()

#endif
