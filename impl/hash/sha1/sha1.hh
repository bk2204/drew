#ifndef SHA1_HH
#define SHA1_HH

#include "hash.hh"
#include "endian.hh"
#include <stdint.h>

namespace drew {

class SHA : public Hash<uint32_t, 20, 20, 64, BigEndian> 
{
	public:
		SHA();
		virtual ~SHA() {}
		template<int Rotate>
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data) = 0;
	private:
};

// The static Transform functions in the derived classes are required because of
// the way the automatic plugin-registration code works.  At some point in the
// future, the code will be reworked to avoid that problem altogether.
class SHA1 : public SHA
{
	public:
		virtual ~SHA1() {}
		static void Transform(quantum_t *state, const uint8_t *data)
		{
			SHA::Transform<1>(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class SHA0 : public SHA
{
	public:
		virtual ~SHA0() {}
		static void Transform(quantum_t *state, const uint8_t *data)
		{
			SHA::Transform<0>(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

}

#endif
