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
#ifndef SKEIN_HH
#define SKEIN_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class Skein : public Hash<uint64_t, 64, 64, 64, LittleEndian>
{
	public:
		Skein(size_t);
		virtual ~Skein() {}
		void Reset();
		virtual void GetDigest(uint8_t *digest, size_t len, bool nopad);
		virtual void Pad();
		void UBI(uint64_t *state, const uint8_t *m, size_t len,
				const uint64_t *tweak);
		void UBIBlock(uint64_t *state, const uint8_t *m, const uint64_t *tweak);
		void UBIBlock(uint64_t *state, const uint64_t *m,
				const uint64_t *tweak);
		void Update(const uint8_t *data, size_t len);
		size_t GetDigestSize() const
		{
			return m_digest_size;
		}
	protected:
		void Transform(const uint8_t *data)
		{
			Transform(data, false);
		}
		void Transform(const uint8_t *data, bool final);
		static void Pad(uint64_t *, uint8_t *, uint32_t *);
		static void Final(uint32_t *);
	private:
		bool full;
		size_t m_digest_size;
		uint64_t m_tweak[2];
};

}
UNHIDE()

#endif
