#ifndef RC2_HH
#define RC2_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

#define MAXROUNDS 14

namespace drew {

class RC2
{
	public:
		typedef LittleEndian endian_t;
		RC2();
		~RC2() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		void Mix(uint16_t *r, size_t i, size_t j, size_t s);
		void MixRound(uint16_t *r, size_t j);
		void Mash(uint16_t *r, size_t i);
		void MashRound(uint16_t *r);
		void RMix(uint16_t *r, size_t i, size_t j, size_t s);
		void RMixRound(uint16_t *r, size_t j);
		void RMash(uint16_t *r, size_t i);
		void RMashRound(uint16_t *r);
		uint16_t m_k[64];
		static const uint8_t pitable[];

};
}

#endif
