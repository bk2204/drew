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
#ifndef SAFER_HH
#define SAFER_HH

#include <stddef.h>
#include <stdint.h>

#include "blockcipher.hh"
#include "util.hh"

HIDE()
namespace drew {

#define MAX_ROUNDS 16
class SAFER : public BlockCipher<8, NonEndian>
{
	public:
		SAFER();
		SAFER(size_t);
		~SAFER() {};
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
	protected:
		static void F(uint8_t &, uint8_t &, uint8_t, uint8_t);
		static void FInverse(uint8_t &, uint8_t &, uint8_t, uint8_t);
		static void DoF(uint8_t *);
		static void DoFInverse(uint8_t *);
		static void ForwardA(uint8_t *, const uint8_t *);
		static void ForwardB(uint8_t *, const uint8_t *);
		static void InverseA(uint8_t *, const uint8_t *);
		static void InverseB(uint8_t *, const uint8_t *);
		static void PermuteForward(uint8_t *, const uint8_t *);
		static void PermuteInverse(uint8_t *, const uint8_t *);
		static void SubstituteForward(uint8_t *);
		static void SubstituteInverse(uint8_t *);
		virtual int SetKeyInternal(const uint8_t *key, size_t sz);
		uint8_t k[(MAX_ROUNDS * 2) + 1][8];
		unsigned rounds;
		static const uint8_t s[256], sinv[256];
	private:
};

}
UNHIDE()

#endif
