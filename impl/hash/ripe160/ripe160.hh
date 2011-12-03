/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#ifndef RIPEMD160_HH
#define RIPEMD160_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class RIPEMD160 : public Hash<uint32_t, 20, 20, 64, LittleEndian>
{
	public:
		RIPEMD160();
		virtual ~RIPEMD160() {}
		void Reset();
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class RIPEMD128 : public Hash<uint32_t, 16, 16, 64, LittleEndian>
{
	public:
		RIPEMD128();
		virtual ~RIPEMD128() {}
		void Reset();
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class RIPEMD320 : public Hash<uint32_t, 40, 40, 64, LittleEndian>
{
	public:
		RIPEMD320();
		virtual ~RIPEMD320() {}
		void Reset();
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class RIPEMD256 : public Hash<uint32_t, 32, 32, 64, LittleEndian>
{
	public:
		RIPEMD256();
		virtual ~RIPEMD256() {}
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
