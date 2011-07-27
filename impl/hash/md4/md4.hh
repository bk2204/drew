#ifndef MD4_HH
#define MD4_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class MD4 : public Hash<uint32_t, 16, 16, 64, LittleEndian>
{
	public:
		MD4();
		virtual ~MD4() {}
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
UNHIDE()

#endif
