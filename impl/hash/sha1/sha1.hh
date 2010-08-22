#ifndef SHA1_HH
#define SHA1_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

namespace drew {

template<int Rotate>
class SHA : public Hash<uint32_t, 20, 20, 64, BigEndian> 
{
	public:
		SHA();
		virtual ~SHA() {}
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

// The static Transform functions in the derived classes are required because of
// the way the automatic plugin-registration code works.  At some point in the
// future, the code will be reworked to avoid that problem altogether.
class SHA1 : public SHA<1>
{
	public:
		virtual ~SHA1() {}
	protected:
	private:
};

class SHA0 : public SHA<0>
{
	public:
		virtual ~SHA0() {}
	protected:
	private:
};

}

#endif
