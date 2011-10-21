/*-
 * This code (which is in the public domain) comes from libcrypto++ 5.6.0.  The
 * original code was written by Phil Karn and Wei Dei, with contributions from
 * Jim Gillogly and Richard Outerbridge.  brian m. carlson converted it to a
 * drew block cipher plugin.
 */
#ifndef DES_HH
#define DES_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class TripleDES;

class DES : public BlockCipher<8, BigEndian>
{
	public:
		DES();
		~DES() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
		void ProcessBlock(const uint32_t *, uint32_t &, uint32_t &) const;
	protected:
	private:
		uint32_t m_k[32], m_kd[32];
		static const uint32_t Spbox[8][64];
		friend class TripleDES;
};

class TripleDES : public BlockCipher<8, BigEndian>
{
	public:
		TripleDES();
		~TripleDES() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		DES m_des1, m_des2, m_des3;

};

}
UNHIDE()

#endif
