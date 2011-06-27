#ifndef ARC4STIR_HH
#define ARC4STIR_HH

#include <sys/types.h>

#include "prng.hh"
#include "keystream.hh"

namespace drew {

class ARC4Stir : public BytePRNG
{
	public:
		ARC4Stir();
		virtual ~ARC4Stir() {
			delete m_ks;
		}
		uint8_t GetByte();
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		void Stir();
		uint8_t InternalGetByte();
		void Stir(const uint8_t *);
		ssize_t m_cnt;
		KeystreamGenerator *m_ks;
	private:
};

}

#endif
