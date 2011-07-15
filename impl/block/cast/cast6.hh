#ifndef CAST6_HH
#define CAST6_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"
#include "cast.hh"

HIDE()
namespace drew {

class CAST6 : public CAST, public BlockCipher<16>
{
	public:
		typedef BigEndian endian_t;
		CAST6();
		~CAST6() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_km[4][12];
		uint8_t m_kr[4][12];
};

}
UNHIDE()

#endif
