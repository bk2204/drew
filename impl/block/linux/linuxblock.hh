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

template<int size, class E>
class LinuxCryptoImplementation : public BlockCipher<size, E>
{
	public:
		typedef typename BlockCipher<size, E>::FastBlock FastBlock;
		LinuxCryptoImplementation() {}
		~LinuxCryptoImplementation()
		{
			memset(keybak, 0, sizeof(keybak));
		}
		int Encrypt(uint8_t *out, const uint8_t *in) const
		{
			const size_t block_size = BlockCipher<size, E>::block_size;
			return af_alg_do_crypt(&alg, out, in, block_size, 0);
		}
		int Decrypt(uint8_t *out, const uint8_t *in) const
		{
			const size_t block_size = BlockCipher<size, E>::block_size;
			return af_alg_do_crypt(&alg, out, in, block_size, 1);
		}
		int EncryptFast(FastBlock *out, const FastBlock *in,
				size_t n) const
		{
			const size_t block_size = BlockCipher<size, E>::block_size;
			return af_alg_do_crypt(&alg, out->data, in->data, block_size*n, 0);
		}
		int DecryptFast(FastBlock *out, const FastBlock *in,
				size_t n) const
		{
			const size_t block_size = BlockCipher<size, E>::block_size;
			return af_alg_do_crypt(&alg, out->data, in->data, block_size*n, 1);
		}
	protected:
		void Clone(const LinuxCryptoImplementation &other)
		{
			this->SetKeyInternal(other.keybak, other.keysz);
		}
		virtual int SetKeyInternal(const uint8_t *key, size_t len)
		{
			if (alg.fd >= 0)
				close(alg.fd);
			if (alg.sockfd >= 0)
				close(alg.sockfd);

			RETFAIL(af_alg_initialize(&alg));
			RETFAIL(af_alg_open_socket(&alg, "skcipher", ecbname));

			memcpy(keybak, key, len);

			RETFAIL(af_alg_set_key(&alg, key, len));
			RETFAIL(af_alg_make_socket(&alg));
			return 0;
		}
		struct af_alg alg;
		uint8_t keybak[32];
		const char *ecbname;
	private:
};

class LinuxAES : public LinuxCryptoImplementation<16, BigEndian>
{
	public:
		LinuxAES();
		LinuxAES(const LinuxAES &);
	protected:
		int SetKeyInternal(const uint8_t *key, size_t len);
	private:
};

class LinuxCAST6 : public LinuxCryptoImplementation<16, BigEndian>
{
	public:
		LinuxCAST6();
		LinuxCAST6(const LinuxCAST6 &);
	protected:
		int SetKeyInternal(const uint8_t *key, size_t len);
	private:
};

class LinuxCAST5 : public LinuxCryptoImplementation<8, BigEndian>
{
	public:
		LinuxCAST5();
		LinuxCAST5(const LinuxCAST5 &);
	protected:
		int SetKeyInternal(const uint8_t *key, size_t len);
	private:
};

}

#endif
