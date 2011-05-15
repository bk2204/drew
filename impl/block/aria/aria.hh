#ifndef ARIA_HH
#define ARIA_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

namespace drew {

class ARIA : public BlockCipher<32>
{
	public:
		typedef BigEndian endian_t;
		ARIA();
		~ARIA() {};
		virtual int SetKey(const uint8_t *key, size_t sz) = 0;
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		typedef AlignedBlock<uint8_t, 16> AlignedData;
		void Permute(uint8_t *out, const uint8_t *in) const;
		inline void sl1(AlignedData &, const AlignedData &,
				const AlignedData &) const;
		inline void sl2(AlignedData &, const AlignedData &,
				const AlignedData &) const;
		inline void afunc(AlignedData &, const AlignedData &) const;
		inline uint8_t combine(const AlignedData &d, unsigned v1, unsigned v2,
				unsigned v3, unsigned v4, unsigned v5, unsigned v6,
				unsigned v7) const;
		inline void fo(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const;
		inline void fe(AlignedData &out, const AlignedData &in,
				const AlignedData &x) const;
		int Encrypt128(uint8_t *, const uint8_t *, const AlignedData *) const;
		int Encrypt192(uint8_t *, const uint8_t *, const AlignedData *) const;
		int Encrypt256(uint8_t *, const uint8_t *, const AlignedData *) const;
		AlignedData m_ek[17], m_dk[17];
		size_t m_off;
		static const uint8_t sb1[], sb2[], sb3[], sb4[];
	private:

};

#if defined(ARIA_128)
// This will only work on targets where 128-bit quantities exist.
class ARIA128 : public ARIA
{
	public:
		int SetKey(const uint8_t *key, size_t sz);
	protected:
		typedef unsigned __int128 uint128_t;
		uint128_t fo128(uint128_t a, uint128_t b) const;
		uint128_t fe128(uint128_t a, uint128_t b) const;
};
#elif defined(ARIA_BYTEWISE)
class ARIABytewise : public ARIA
{
	public:
		int SetKey(const uint8_t *key, size_t sz);
	protected:
		void RotateRightAndXor(AlignedData &out, const AlignedData &in,
				const AlignedData &x, size_t offset) const;
};
#endif
}

#endif
