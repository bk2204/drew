/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#ifndef SHA1_HH
#define SHA1_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

template<int Rotate>
class SHA : public Hash<uint32_t, 20, 20, 64, BigEndian>
{
	public:
		SHA();
		virtual ~SHA() {}
		void Reset();
		static void ForwardTransform(quantum_t *state, const quantum_t *data);
		static void InverseTransform(quantum_t *state, const quantum_t *data);
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
UNHIDE()

#endif
