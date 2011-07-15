#ifndef RABBIT_HH
#define RABBIT_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

HIDE()
namespace drew {

class RabbitKeystream
{
	public:
		typedef LittleEndian endian_t;
		RabbitKeystream();
		~RabbitKeystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *, size_t sz);
		void Reset();
		void GetValue(uint32_t val[4]);
		void FillBuffer(uint8_t val[16]);
	protected:
	private:
		inline uint64_t square(uint32_t term) const;
		inline uint32_t g(uint32_t u, uint32_t v) const;
		inline void Iterate();
		uint32_t x[8] ALIGNED_T;
		uint32_t c[8] ALIGNED_T;
		bool b;
};


class Rabbit
{
	public:
		Rabbit();
		Rabbit(size_t drop);
		~Rabbit() {}
		void Reset();
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		RabbitKeystream m_ks;
		uint8_t m_key[16];
		uint8_t m_nonce[8];
		uint8_t m_buf[16] ALIGNED_T;
		size_t m_nbytes;
};

}
UNHIDE()

#endif
