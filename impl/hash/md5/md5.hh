#ifndef MD5_HH
#define MD5_HH

#include "hash.hh"
#include "endian.hh"
#include <stdint.h>

namespace drew {

class MD5 : public Hash<uint32_t, 16, 16, 64, LittleEndian>
{
	public:
		MD5();
		virtual ~MD5() {}
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
