#ifndef GRIJNDAEL_HH
#define GRIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

#define MAXROUNDS 14

namespace drew {

class Rijndael
{
	public:
		typedef BigEndian endian_t;
		Rijndael();
		~Rijndael() {};
		virtual int SetKey(const uint8_t *key, size_t sz) = 0;
		virtual int Encrypt(uint8_t *out, const uint8_t *in) const = 0;
		virtual int Decrypt(uint8_t *out, const uint8_t *in) const;
		virtual size_t GetBlockSize() const = 0;
	protected:
		size_t m_nr, m_nk;
		const uint8_t *m_sh1;
		static const uint8_t shifts1[5][4];
		uint64_t m_rk[MAXROUNDS+1][4];
		uint8_t m_rkb[sizeof(uint64_t) * (MAXROUNDS+1) * 4];
		inline void KeyAddition(uint64_t *, const uint64_t *) const;
		static const uint8_t mult2[];
		static const uint8_t mult3[];
		static const uint8_t mult9[];
		static const uint8_t multb[];
		static const uint8_t multd[];
		static const uint8_t multe[];
		static const uint8_t S[];
		static const uint32_t Et0[], Et1[], Et2[], Et3[];
		inline virtual void DecryptBlock(uint64_t *) const;
		static const uint8_t rcon[];
	private:
		inline void Substitution(uint64_t *, const uint8_t *) const;
		virtual void ShiftRow(uint64_t *, const uint8_t *) const = 0;
		virtual uint64_t ApplyS(uint64_t, const uint8_t *) const = 0;
		virtual void InvMixColumn(uint64_t *) const = 0;
		virtual void PackBlock(uint8_t *, const uint64_t *) const = 0;
		virtual void UnpackBlock(uint64_t *, const uint8_t *) const = 0;
		void SetKeyDecrypt(void);
		static const uint8_t Si[];
		static const uint8_t shifts0[5][4];

};

template<unsigned BlockSize>
class GenericRijndael : public Rijndael, public BlockCipher<BlockSize/8>
{
	public:
		static const size_t block_size = BlockSize / 8;
		int SetKey(const uint8_t *key, size_t sz);
		int Encrypt(uint8_t *, const uint8_t *) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const
		{
			return Rijndael::Decrypt(out, in);
		}
	protected:
		static const size_t m_nb = BlockSize / 32;
		static const size_t m_bc = BlockSize / 4;
		static const uint64_t m_bcmask = (((uint64_t(1) << (m_bc-1))-1)<<1)|1;
		static const size_t shiftoffset = (m_nb-4);
		inline uint64_t shift(uint64_t x, unsigned n) const
		{
			return ((x >> n) | (x << (m_bc - n))) & m_bcmask;
		}
		size_t GetBlockSize() const
		{
			return block_size;
		}
		inline void ShiftRow(uint64_t *, const uint8_t *) const;
		inline uint64_t ApplyS(uint64_t, const uint8_t *) const;
		inline void InvMixColumn(uint64_t *) const;
		inline void PackBlock(uint8_t *, const uint64_t *) const;
		inline void UnpackBlock(uint64_t *, const uint8_t *) const;
		inline virtual void EncryptBlock(uint8_t *) const;
		virtual void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const = 0;
		virtual void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const = 0;
};

class Rijndael128 : public GenericRijndael<128>
{
	public:
		Rijndael128() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const;
		void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const;
};

class Rijndael160 : public GenericRijndael<160>
{
	public:
		Rijndael160() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const;
		void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const;
};

class Rijndael192 : public GenericRijndael<192>
{
	public:
		Rijndael192() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const;
		void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const;
};

class Rijndael224 : public GenericRijndael<224>
{
	public:
		Rijndael224() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const;
		void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const;
};

class Rijndael256 : public GenericRijndael<256>
{
	public:
		Rijndael256() { m_sh1 = shifts1[shiftoffset]; }
	protected:
		void Round(uint8_t *, const uint8_t *, const uint8_t *rk,
				const uint8_t *s) const;
		void Final(uint8_t *, uint8_t *state, const uint8_t *rk,
				const uint8_t *s) const;
};


}

#endif
