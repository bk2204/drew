#ifndef TEA_HH
#define TEA_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class TEA : public BlockCipher<8>
{
	public:
		typedef BigEndian endian_t;
		TEA();
		~TEA() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_k[4];

};
}

#endif
