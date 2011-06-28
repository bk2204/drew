#ifndef SALSA20_HH
#define SALSA20_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class Salsa20Keystream
{
	public:
		typedef LittleEndian endian_t;
		Salsa20Keystream();
		~Salsa20Keystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void Reset();
		void FillBuffer(uint8_t *);
		void FillBufferAligned(uint8_t *);
	protected:
	private:
		struct AlignedData
		{
			uint32_t buf[16] ALIGNED_T;
		};
		virtual void DoHash(AlignedData &cur);
		AlignedData state;
		size_t keysz;
		uint64_t ctr;
};

class Salsa20
{
	public:
		Salsa20();
		~Salsa20() {}
		void Reset();
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
		void EncryptFast(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		Salsa20Keystream m_ks;
		uint8_t m_buf[64];
		size_t m_nbytes;
};

}

#endif
