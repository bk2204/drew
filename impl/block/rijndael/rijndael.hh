#ifndef GRIJNDAEL_HH
#define GRIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "endian.hh"

#define MAXROUNDS 14

namespace drew {

class Rijndael
{
	public:
		typedef BigEndian endian_t;
		Rijndael(size_t blocksz);
		~Rijndael() {};
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in);
		void Decrypt(uint8_t *out, const uint8_t *in);
	protected:
	private:
		void KeyAddition(uint64_t *);
		void ShiftRow(const uint8_t *);
		void Substitution(const uint8_t *);
		uint64_t ApplyS(uint64_t, const uint8_t *);
		void MixColumn();
		void InvMixColumn();
		void EncryptBlock();
		void DecryptBlock();
		void PackBlock(uint8_t *);
		void UnpackBlock(const uint8_t *);
		inline uint8_t mul0x2(int b)
		{
			return b ? aLogtable[25 + (logtable[b] & 0xff)]: 0;
		}
		inline uint8_t mul0x3(int b)
		{
			return b ? aLogtable[1 + (logtable[b] & 0xff)] : 0;
		}
		inline uint8_t mul0x9(int b)
		{
			return b >= 0 ? aLogtable[199 + b] : 0;
		}
		inline uint8_t mul0xb(int b)
		{
			return b >= 0 ? aLogtable[104 + b] : 0;
		}
		inline uint8_t mul0xd(int b)
		{
			return b >= 0 ? aLogtable[238 + b] : 0;
		}
		inline uint8_t mul0xe(int b)
		{
			return b >= 0 ? aLogtable[223 + b] : 0;
		}
		inline uint64_t shift(uint64_t x, unsigned n)
		{
			return ((x >> n) | (x << (m_bc - n))) & m_bcmask;
		}
		void SetKeyDecrypt(void);
		size_t m_nr, m_nk, m_nb, m_bc;
		uint64_t m_bcmask;
		const uint8_t *m_sh0, *m_sh1;
		uint64_t m_a0, m_a1, m_a2, m_a3;
		uint64_t m_rk[MAXROUNDS+1][4];
		static const uint8_t aLogtable[];
		static const uint8_t logtable[];
		static const uint8_t S[];
		static const uint8_t Si[];
		static const uint8_t shifts0[5][4];
		static const uint8_t shifts1[5][4];
		static const uint8_t rcon[];

};

}

#endif
