#ifndef XTEA_HH
#define XTEA_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class XTEA : public BlockCipher<8>
{
	public:
		typedef BigEndian endian_t;
		XTEA() : rounds(32) {}
		XTEA(size_t r) : rounds(r) {}
		~XTEA() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_k[4];
		size_t rounds;

};
}

#endif
