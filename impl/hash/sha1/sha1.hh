#ifndef SHA1_HH
#define SHA1_HH

#include "hash.hh"
#include "endian.hh"
#include <stdint.h>

namespace drew {

class SHA1 : public Hash<uint32_t, 20, 20, 64, BigEndian>
{
	public:
		SHA1();
		virtual ~SHA1() {}
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

}

#endif
