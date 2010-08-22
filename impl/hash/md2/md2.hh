#ifndef MD2_HH
#define MD2_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

namespace drew {

class MD2 : public Hash<uint8_t, 16, 64, 16, LittleEndian>
{
	public:
		MD2();
		virtual ~MD2() {}
		void Pad();
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
		static const uint8_t sbox[256];
		uint8_t *m_csum;
		uint8_t m_l;
	private:
};

}

#endif
