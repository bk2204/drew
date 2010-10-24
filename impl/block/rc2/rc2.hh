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
		inline void Mix(uint16_t *r, size_t i, size_t j, size_t s);
		inline void MixRound(uint16_t *r, size_t j);
		inline void Mash(uint16_t *r, size_t i);
		inline void MashRound(uint16_t *r);
		inline void RMix(uint16_t *r, size_t i, size_t j, size_t s);
		inline void RMixRound(uint16_t *r, size_t j);
		inline void RMash(uint16_t *r, size_t i);
		inline void RMashRound(uint16_t *r);
		uint16_t m_k[64];
		static const uint8_t pitable[];

};
}

#endif
