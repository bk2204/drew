#ifndef RIJNDAEL_HH
#define RIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class AES : public BlockCipher<16>
{
	public:
		typedef BigEndian endian_t;
		AES();
		~AES() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
	private:
		void SetKeyEncrypt(const uint8_t *key, size_t sz);
		void SetKeyDecrypt(void);
		static void EncryptRound(uint32_t *t, const uint32_t *s,
				const uint32_t *rk);
		static void DecryptRound(uint32_t *t, const uint32_t *s,
				const uint32_t *rk);
		static const size_t m_nb;
		size_t m_nr, m_nk;
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

#endif
