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
#ifndef ISAACPLUS_HH
#define ISAACPLUS_HH

#include <sys/types.h>

#include "prng.hh"

HIDE()
namespace drew {

class IsaacPlus : public BlockPRNG
{
	public:
		IsaacPlus();
		virtual ~IsaacPlus() {}
		int GetBytes(uint8_t *, size_t);
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		void Stir();
		void Stir(const uint32_t *);
		void FillBuffer(uint32_t *);
		uint32_t Round(uint32_t, uint32_t &, uint32_t &, uint32_t *,
				const uint32_t *);
		uint32_t m_aa, m_bb, m_cc;
		uint32_t m_s[256], m_res[256];
		size_t m_nbytes;
	private:
};

}
UNHIDE()

#endif
