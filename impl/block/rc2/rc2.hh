#ifndef RC2_HH
#define RC2_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class RC2 : public BlockCipher<8>
{
	public:
		typedef LittleEndian endian_t;
		RC2();
		~RC2() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		inline void Mix(uint16_t *r, size_t i, size_t j, size_t s) const;
		inline void MixRound(uint16_t *r, size_t j) const;
		inline void Mash(uint16_t *r, size_t i) const;
		inline void MashRound(uint16_t *r) const;
		inline void RMix(uint16_t *r, size_t i, size_t j, size_t s) const;
		inline void RMixRound(uint16_t *r, size_t j) const;
		inline void RMash(uint16_t *r, size_t i) const;
		inline void RMashRound(uint16_t *r) const;
		uint16_t m_k[64];
		static const uint8_t pitable[];

};
}
UNHIDE()

#endif
