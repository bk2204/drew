#ifndef SERPENT_HH
#define SERPENT_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class Serpent
{
	public:
		typedef LittleEndian endian_t;
		static const size_t block_size = 16;
		Serpent();
		~Serpent() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		uint32_t m_keybuf[140];
		uint32_t *m_key;

};

}

#endif
