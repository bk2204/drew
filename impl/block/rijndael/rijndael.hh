/*-
 * Copyright © 2000–2009 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)
 * Copyright © 2010–2011 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef GRIJNDAEL_HH
#define GRIJNDAEL_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

#define MAXROUNDS 14

HIDE()
namespace drew {

class Rijndael
{
	public:
		Rijndael();
		virtual ~Rijndael() {};
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
class GenericRijndael : public Rijndael,
	public BlockCipher<BlockSize/8, BigEndian>
{
	public:
		static const size_t block_size = BlockSize / 8;
		int Encrypt(uint8_t *, const uint8_t *) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const
		{
			return Rijndael::Decrypt(out, in);
		}
		int SetKey(const uint8_t *key, size_t sz)
		{
			return this->BlockCipher<BlockSize/8, BigEndian>::SetKey(key, sz);
		}
	protected:
		int SetKeyInternal(const uint8_t *key, size_t sz);
		static const size_t m_nb;
		static const size_t m_bc;
		static const uint64_t m_bcmask;
		static const size_t shiftoffset;
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
UNHIDE()

#endif
