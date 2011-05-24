#ifndef KEYSTREAM_HH
#define KEYSTREAM_HH

#include <sys/types.h>

#include "prng.hh"

namespace drew {

class KeystreamGenerator
{
	public:
		KeystreamGenerator(int index);
		~KeystreamGenerator();
		uint8_t GetByte();
		void Stir(const uint8_t *, uint8_t);
	protected:
		uint8_t m_i, m_j;
		uint8_t m_s[256];
		static const uint8_t rc2table[256], md2table[256], ariatable[256],
					 ariatable2[256];
	private:
};

}

#endif
