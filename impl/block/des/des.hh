#ifndef RIJNDAEL_HH
#define RIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class TripleDES;

class DES
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 8;
		DES();
		~DES() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
		void ProcessBlock(const uint32_t *, uint32_t &, uint32_t &) const;
	protected:
	private:
		uint32_t m_k[32], m_kd[32];
		static const uint32_t Spbox[8][64];
		friend class TripleDES;
};

class TripleDES
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 8;
		TripleDES();
		~TripleDES() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		DES m_des1, m_des2, m_des3;

};

}

#endif
