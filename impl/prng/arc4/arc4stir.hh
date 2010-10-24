#ifndef ARC4STIR_HH
#define ARC4STIR_HH

#include "prng.hh"

namespace drew {

class ARC4Stir : public PRNG
{
	public:
		ARC4Stir();
		virtual ~ARC4Stir() {}
		uint8_t GetByte();
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		void Stir();
		uint8_t InternalGetByte();
		void Stir(const uint8_t *);
		uint8_t m_i, m_j;
		uint8_t m_s[256];
		static const uint8_t pitable[256];
	private:
};

}

#endif
