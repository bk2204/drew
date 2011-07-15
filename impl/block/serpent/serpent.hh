#ifndef SERPENT_HH
#define SERPENT_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class Serpent : public BlockCipher<16>
{
	public:
		typedef LittleEndian endian_t;
		Serpent();
		~Serpent() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_keybuf[140];
		uint32_t *m_key;

};

}
UNHIDE()

#endif
