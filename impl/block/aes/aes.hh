/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#ifndef RIJNDAEL_HH
#define RIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

HIDE()
namespace drew {

class AES : public BlockCipher<16, BigEndian>
{
	public:
		AES();
		~AES() {};
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		int SetKeyInternal(const uint8_t *key, size_t sz);
		void SetKeyEncrypt(const uint8_t *key, size_t sz);
		void SetKeyDecrypt(void);
		static inline void EncryptRound(uint32_t &t0, uint32_t &t1,
				uint32_t &t2, uint32_t &t3, uint32_t s0, uint32_t s1,
				uint32_t s2, uint32_t s3, const uint32_t *rk);
		static inline void DecryptRound(uint32_t &t0, uint32_t &t1,
				uint32_t &t2, uint32_t &t3, uint32_t s0, uint32_t s1,
				uint32_t s2, uint32_t s3, const uint32_t *rk);
		static const size_t m_nb;
		size_t m_nr, m_nk, m_nri;
		// maxnb*(maxnr+1) = 8 * 9 = 72
		uint32_t m_rk[72], m_rkd[72];	
		uint32_t m_km[16];
		uint8_t m_kr[16];
		static const uint32_t Te0[256];
		static const uint32_t Te1[256];
		static const uint32_t Te2[256];
		static const uint32_t Te3[256];
		static const uint32_t Te4[256];
		static const uint32_t Td0[256];
		static const uint32_t Td1[256];
		static const uint32_t Td2[256];
		static const uint32_t Td3[256];
		static const uint32_t Td4[256];
		static const uint32_t rcon[];

};

}
UNHIDE()

#endif
