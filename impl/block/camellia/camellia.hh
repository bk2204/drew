#ifndef BLOWFISH_HH
#define BLOWFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class Camellia : public BlockCipher<16>
{
	public:
		typedef BigEndian endian_t;
		Camellia();
		~Camellia() {};
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		void SetKey128(uint64_t k[4]);
		void SetKey192(uint64_t k[4]);
		void SetKey256(uint64_t k[4]);
		void Encrypt128(uint64_t d[2]) const;
		void Encrypt256(uint64_t d[2]) const;
		void Decrypt128(uint64_t d[2]) const;
		void Decrypt256(uint64_t d[2]) const;
		inline void EncryptPair(uint64_t &, uint64_t &, unsigned) const;
		inline void DecryptPair(uint64_t &, uint64_t &, unsigned) const;
		uint64_t f(uint64_t x, uint64_t k) const;
		uint64_t fl(uint64_t x, uint64_t k) const;
		uint64_t flinv(uint64_t y, uint64_t k) const;
		uint64_t spfunc(uint64_t x) const;
		uint64_t kw[4];
		uint64_t ku[24];
		uint64_t kl[6];
		void (Camellia::*fenc)(uint64_t d[2]) const;
		void (Camellia::*fdec)(uint64_t d[2]) const;
		static const uint64_t s[8][256];
	private:
};

}

#endif
