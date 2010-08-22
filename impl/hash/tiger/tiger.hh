#ifndef SHA512_HH
#define SHA512_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

namespace drew {

class Tiger : public Hash<uint64_t, 24, 24, 64, LittleEndian>
{
	public:
		Tiger();
		virtual ~Tiger() {}
		static void Transform(uint64_t *state, const uint8_t *data);
		void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
		static const uint64_t t1[], t2[], t3[], t4[];
};
}

#endif
