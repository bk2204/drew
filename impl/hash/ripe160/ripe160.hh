#ifndef RIPEMD160_HH
#define RIPEMD160_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

namespace drew {

class RIPEMD160 : public Hash<uint32_t, 20, 20, 64, LittleEndian>
{
	public:
		RIPEMD160();
		virtual ~RIPEMD160() {}
		void Reset();
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
