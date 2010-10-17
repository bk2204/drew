#ifndef CAST6_HH
#define CAST6_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"
#include "cast.hh"

namespace drew {

class CAST6 : public CAST
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 16;
		CAST6();
		~CAST6() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		uint32_t m_km[4][12];
		uint8_t m_kr[4][12];
};

}

#endif
