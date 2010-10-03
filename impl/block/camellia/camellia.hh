#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class Camellia
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 16;
		Camellia();
		~Camellia() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
		void SetKey128(uint64_t k[4]);
		void SetKey192(uint64_t k[4]);
		void SetKey256(uint64_t k[4]);
		void Encrypt128(uint64_t d[2]);
		void Encrypt256(uint64_t d[2]);
		void Decrypt128(uint64_t d[2]);
		void Decrypt256(uint64_t d[2]);
		uint64_t f(uint64_t x, uint64_t k);
		uint64_t fl(uint64_t x, uint64_t k);
		uint64_t flinv(uint64_t y, uint64_t k);
		uint64_t spfunc(uint64_t x);
		uint64_t kw[4];
		uint64_t ku[24];
		uint64_t kl[6];
		void (Camellia::*fenc)(uint64_t d[2]);
		void (Camellia::*fdec)(uint64_t d[2]);
		static const uint64_t s[8][256];
	private:
};

}

#endif
