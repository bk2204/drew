/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#ifndef SHACAL_HH
#define SHACAL_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class SHACAL1 : public BlockCipher<20>
{
	public:
		typedef BigEndian endian_t;
		SHACAL1();
		~SHACAL1() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_words[80];
};

class SHACAL2 : public BlockCipher<32>
{
	public:
		typedef BigEndian endian_t;
		SHACAL2();
		~SHACAL2() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		uint32_t m_words[64];
};

}
UNHIDE()

#endif
