#ifndef RIJNDAEL_HH
#define RIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class AES
{
	public:
		typedef BigEndian endian_t;
		AES(size_t blocksz);
		~AES() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		void SetKeyEncrypt(const uint8_t *key, size_t sz);
		void SetKeyDecrypt(void);
		size_t m_nr, m_nk, m_nb;
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
