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
#ifndef LINUXAES_HH
#define LINUXAES_HH

#include <stddef.h>
#include <stdint.h>

#include "block-plugin.hh"
#include "util.hh"

#include "../../multi/linux/af-alg.h"

namespace drew {

class LinuxAES : public BlockCipher<16, BigEndian>
{
	public:
		LinuxAES();
		LinuxAES(const LinuxAES &);
		~LinuxAES() { memset(keybak, 0, sizeof(keybak)); };
		int Encrypt(uint8_t *out, const uint8_t *in) const;
		int Decrypt(uint8_t *out, const uint8_t *in) const;
		int EncryptFast(FastBlock *bout, const FastBlock *bin,
				size_t n) const;
		int DecryptFast(FastBlock *bout, const FastBlock *bin,
				size_t n) const;
	protected:
		int SetKeyInternal(const uint8_t *key, size_t len);
	private:
		struct af_alg alg;
		uint8_t keybak[32];
};

}

#endif
