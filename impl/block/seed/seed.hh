#ifndef SEED_HH
#define SEED_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class SEED : public BlockCipher<16>
{
	public:
		typedef BigEndian endian_t;
		SEED();
		~SEED() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		static inline uint64_t GenerateSubkey(uint32_t k[4], uint32_t kci);
		static inline uint64_t OddKey(uint32_t k[4], uint32_t kci);
		static inline uint64_t EvenKey(uint32_t k[4], uint32_t kci);
		static inline uint64_t f(uint64_t k, uint64_t r);
		static inline uint32_t g(uint32_t x);
		static const uint32_t ss0[], ss1[], ss2[], ss3[];
	private:
		uint64_t m_k[16];

};
}

#endif
