#ifndef CAST5_HH
#define CAST5_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"
#include "cast.hh"

namespace drew {

class CAST5 : public CAST, public BlockCipher<8>
{
	public:
		typedef BigEndian endian_t;
		CAST5();
		~CAST5() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		void SetUpEndianness();
		void ComputeZSet(uint32_t *z, const uint32_t *x);
		void ComputeXSet(uint32_t *x, const uint32_t *z);
		void ComputeSubkeySetA(uint32_t *sk, const uint32_t *z, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeySetB(uint32_t *sk, const uint32_t *z, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeys(const uint8_t *k);
		uint32_t m_km[16];
		uint8_t m_kr[16];
};

}

#endif
