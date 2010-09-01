#ifndef GRIJNDAEL_HH
#define GRIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

#define MAXROUNDS 14

namespace drew {

class Rijndael
{
	public:
		typedef BigEndian endian_t;
		//Rijndael(size_t blocksz);
		Rijndael();
		~Rijndael() {};
		virtual void SetKey(const uint8_t *key, size_t sz) = 0;
		virtual void Encrypt(uint8_t *out, const uint8_t *in);
		virtual void Decrypt(uint8_t *out, const uint8_t *in);
		virtual size_t GetBlockSize() const = 0;
	protected:
		virtual void Modify(uint64_t *, const uint8_t *) = 0;
		size_t m_nr, m_nk;
		const uint8_t *m_sh1;
		static const uint8_t shifts1[5][4];
		uint64_t m_rk[MAXROUNDS+1][4];
		inline void KeyAddition(uint64_t *, const uint64_t *);
		inline virtual void Round(uint64_t *state, const uint64_t *rk,
				const uint8_t *s) = 0;
		static const uint8_t mult2[];
		static const uint8_t mult3[];
		static const uint8_t mult9[];
		static const uint8_t multb[];
		static const uint8_t multd[];
		static const uint8_t multe[];
		static const uint8_t S[];
		inline virtual void EncryptBlock(uint64_t *);
		inline virtual void DecryptBlock(uint64_t *);
	private:
		inline void Substitution(uint64_t *, const uint8_t *);
		inline virtual void ShiftRow(uint64_t *, const uint8_t *) = 0;
		inline virtual uint64_t ApplyS(uint64_t, const uint8_t *) = 0;
		inline virtual void MixColumn(uint64_t *) = 0;
		inline virtual void InvMixColumn(uint64_t *) = 0;
		inline virtual void PackBlock(uint8_t *, const uint64_t *) = 0;
		inline virtual void UnpackBlock(uint64_t *, const uint8_t *) = 0;
		void SetKeyDecrypt(void);
		static const uint8_t Si[];
		static const uint8_t shifts0[5][4];
		static const uint8_t rcon[];

};

template<unsigned BlockSize>
class GenericRijndael : public Rijndael
{
	public:
		static const size_t block_size = BlockSize / 8;
	protected:
		uint8_t m_rkb[sizeof(m_rk)];
		static const size_t m_nb = BlockSize / 32;
		static const size_t m_bc = BlockSize / 4;
		static const uint64_t m_bcmask = (((uint64_t(1) << (m_bc-1))-1)<<1)|1;
		static const size_t shiftoffset = (m_nb-4);
		inline uint64_t shift(uint64_t x, unsigned n)
		{
			return ((x >> n) | (x << (m_bc - n))) & m_bcmask;
		}
		size_t GetBlockSize() const
		{
			return block_size;
		}
		virtual void SetKey(const uint8_t *key, size_t sz);
		inline void ShiftRow(uint64_t *, const uint8_t *);
		inline uint64_t ApplyS(uint64_t, const uint8_t *);
		inline void MixColumn(uint64_t *);
		inline void InvMixColumn(uint64_t *);
		inline void PackBlock(uint8_t *, const uint64_t *);
		inline void UnpackBlock(uint64_t *, const uint8_t *);
		inline virtual void Round(uint64_t *state, const uint64_t *rk,
				const uint8_t *s)
		{
			KeyAddition(state, rk);
			Modify(state, s);
			MixColumn(state);
		}
};

class Rijndael128 : public GenericRijndael<128>
{
	public:
		Rijndael128() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		virtual void SetKey(const uint8_t *key, size_t sz);
		virtual void Modify(uint64_t *, const uint8_t *);
		inline virtual void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s);
		inline virtual void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s);
		inline void EncryptBlock(uint8_t *);
		void Encrypt(uint8_t *, const uint8_t *);
};

class Rijndael160 : public GenericRijndael<160>
{
	public:
		Rijndael160() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		virtual void Modify(uint64_t *, const uint8_t *);
};

class Rijndael192 : public GenericRijndael<192>
{
	public:
		Rijndael192() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		virtual void Modify(uint64_t *, const uint8_t *);
};

class Rijndael224 : public GenericRijndael<224>
{
	public:
		Rijndael224() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		virtual void Modify(uint64_t *, const uint8_t *);
};

class Rijndael256 : public GenericRijndael<256>
{
	public:
		Rijndael256() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		virtual void Modify(uint64_t *, const uint8_t *);
};


}

#endif
