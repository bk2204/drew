/*-
 * Copyright © 2010–2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#ifndef BLOCKCIPHER_HH
#define BLOCKCIPHER_HH

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <new>

#include <drew/block.h>
#include "util.hh"

HIDE()
namespace drew {
	template<size_t BlockSize, class E>
	class BlockCipher {
		public:
			static const size_t block_size = BlockSize;
			typedef E endian_t;
			typedef AlignedBlock<uint8_t, BlockSize> FastBlock;
			virtual ~BlockCipher() {}
			virtual int Reset()
			{
				return 0;
			}
			virtual int SetKey(const uint8_t *key, size_t len)
			{
				keysz = len;
				return SetKeyInternal(key, len);
			}
			virtual int GetKeySize() const
			{
				return keysz;
			}
			virtual int TestAvailability()
			{
				return 0;
			}
			virtual int Encrypt(uint8_t *out, const uint8_t *in) const = 0;
			virtual int Decrypt(uint8_t *out, const uint8_t *in) const = 0;
			virtual int EncryptFast(FastBlock *bout, const FastBlock *bin,
					size_t n) const
			{
				// This takes minimal, if any, advantage of the alignment.
				if (BlockSize == 8) {
					for (size_t i = 0; i < n/2; i++, bout++, bin++) {
						Encrypt(bout->data, bin->data);
						Encrypt(bout->data+8, bin->data+8);
					}
				}
				else if (BlockSize == 16)
					for (size_t i = 0; i < n; i++, bout++, bin++)
						Encrypt(bout->data, bin->data);
				else {
					size_t off = 0;
					for (size_t i = 0; i < n; i++, off += BlockSize)
						Encrypt(bout->data+off, bin->data+off);
				}
				return 0;
			}
			virtual int DecryptFast(FastBlock *bout, const FastBlock *bin,
					size_t n) const
			{
				if (BlockSize == 8) {
					for (size_t i = 0; i < n/2; i++, bout++, bin++) {
						Decrypt(bout->data, bin->data);
						Decrypt(bout->data+8, bin->data+8);
					}
				}
				else if (BlockSize == 16)
					for (size_t i = 0; i < n; i++, bout++, bin++)
						Decrypt(bout->data, bin->data);
				else {
					size_t off = 0;
					for (size_t i = 0; i < n; i++, off += BlockSize)
						Decrypt(bout->data+off, bin->data+off);
				}
				return 0;
			}
		protected:
			virtual int SetKeyInternal(const uint8_t *key, size_t len) = 0;
			size_t keysz;
		private:
	};
}
UNHIDE()

#endif
