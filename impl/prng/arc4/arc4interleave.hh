#ifndef ARC4INTERLEAVE_HH
#define ARC4INTERLEAVE_HH

#include <sys/types.h>

#include "prng.hh"
#include "keystream.hh"

HIDE()
namespace drew {

class ARC4Interleave : public BytePRNG
{
	public:
		ARC4Interleave();
		virtual ~ARC4Interleave() {
			for (int i = 0; i < 4; i++)
				delete m_ks[i];
		}
		uint8_t GetByte();
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		uint8_t InternalGetByte();
		void Stir();
		ssize_t m_cnt;
		int m_index;
		KeystreamGenerator *m_ks[4];
	private:
};

}
UNHIDE()

#endif
