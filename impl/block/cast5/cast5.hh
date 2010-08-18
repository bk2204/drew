#ifndef CAST5_HH
#define CAST5_HH

#include <stddef.h>
#include <stdint.h>

#include "endian.hh"

namespace drew {

class CAST5
{
	public:
		typedef BigEndian endian_t;
		static const size_t block_size = 8;
		CAST5();
		~CAST5() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
		static inline uint32_t rol(uint32_t x, uint32_t n)
		{
			return (x << n) | (x >> (32-n));
		}
#define item(x) (m_s[x][endian_t::GetByte(val, 3-x)])
		inline uint32_t f1(uint32_t x, uint32_t km, uint8_t kr)
		{
			const uint32_t val = rol(km + x, kr);
		
			return ((item(0) ^ item(1)) - item(2)) + item(3);
		}
		
		inline uint32_t f2(uint32_t x, uint32_t km, uint8_t kr)
		{
			const uint32_t val = rol(km ^ x, kr);
		
			return ((item(0) - item(1)) + item(2)) ^ item(3);
		}
		
		inline uint32_t f3(uint32_t x, uint32_t km, uint8_t kr)
		{
			const uint32_t val = rol(km - x, kr);
		
			return ((item(0) + item(1)) ^ item(2)) - item(3);
		}
	private:
		void SetUpEndianness();
		void ComputeZSet(uint32_t *z, const uint32_t *x, const uint8_t *xb);
		void ComputeXSet(uint32_t *x, const uint32_t *z, const uint8_t *zb);
		void ComputeSubkeySetA(uint32_t *sk, const uint8_t *zb, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeySetB(uint32_t *sk, const uint8_t *zb, uint8_t a,
				uint8_t b, uint8_t c, uint8_t d);
		void ComputeSubkeys(const uint8_t *k);
		uint8_t m_perm[16];
		static const uint32_t m_s[8][256];
		uint32_t m_km[16];
		uint8_t m_kr[16];
};

}

#endif
