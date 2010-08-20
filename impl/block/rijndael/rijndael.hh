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
		inline void KeyAddition(uint64_t *, const uint64_t *);
		inline void ShiftRow(uint64_t *, const uint8_t *);
		inline void Substitution(uint64_t *, const uint8_t *);
		inline uint64_t ApplyS(uint64_t, const uint8_t *);
		inline void MixColumn(uint64_t *);
		inline void InvMixColumn(uint64_t *);
		inline void EncryptBlock(uint64_t *);
		inline void DecryptBlock(uint64_t *);
		inline void PackBlock(uint8_t *, const uint64_t *);
		inline void UnpackBlock(uint64_t *, const uint8_t *);
		static const uint8_t mult2[];
		static const uint8_t mult3[];
		static const uint8_t mult9[];
		static const uint8_t multb[];
		static const uint8_t multd[];
		static const uint8_t multe[];
		inline uint64_t shift(uint64_t x, unsigned n)
		{
			return ((x >> n) | (x << (m_bc - n))) & m_bcmask;
		}
		void SetKeyDecrypt(void);
		size_t m_nr, m_nk, m_nb, m_bc;
		uint64_t m_bcmask;
		const uint8_t *m_sh0, *m_sh1;
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
