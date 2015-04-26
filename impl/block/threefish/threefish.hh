/*-
 * Copyright © 2011 brian m. carlson
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
/* This implements Threefish-512 only. */
#ifndef THREEFISH_HH
#define THREEFISH_HH

#include <stddef.h>
#include <stdint.h>

#include "blockcipher.hh"
#include "util.hh"

HIDE()
namespace drew {

class Threefish : public BlockCipher<64, LittleEndian>
{
	public:
		Threefish(const uint64_t *t);
		~Threefish() {};
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Encrypt(uint64_t *out, const uint64_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint64_t *out, const uint64_t *in) const;
		int SetKey(const uint64_t *key);
		int SetKey(const uint8_t *key, size_t len)
		{
			return SetKey(key, len, 0);
		}
		int SetKey(const uint8_t *key, size_t len, int mode)
		{
			return BlockCipher<64, LittleEndian>::SetKey(key, len, mode);
		}
	protected:
		inline void InjectKey(uint64_t *x, const size_t r) const;
		int SetKeyInternal(const uint8_t *key, size_t sz);
	private:
		uint64_t m_t[3];
		uint64_t m_k[(72/4)+1][8] ALIGNED_T;
};

}
UNHIDE()

#endif
