#ifndef WHIRLPOOL_HH
#define WHIRLPOOL_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

namespace drew {

class Whirlpool : public Hash<uint64_t, 64, 64, 64, BigEndian>
{
	public:
		Whirlpool();
		virtual ~Whirlpool() {}
		virtual void Reset();
		static void Transform(uint64_t *state, const uint8_t *data);
		void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
		static const uint64_t C0[256], C1[256], C2[256], C3[256];
		static const uint64_t C4[256], C5[256], C6[256], C7[256];
		static const uint64_t rc[10];
	private:
};

}

#endif
