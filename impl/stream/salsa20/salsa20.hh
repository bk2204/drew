/*-
 * Copyright © 2011 brian m. carlson
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
#ifndef SALSA20_HH
#define SALSA20_HH

#include <stddef.h>
#include <stdint.h>

#include "salsa.h"
#include "util.hh"

HIDE()
namespace drew {

class Salsa20GenericKeystream
{
	public:
		typedef LittleEndian endian_t;
		Salsa20GenericKeystream() {}
		~Salsa20GenericKeystream() {}
		virtual Salsa20GenericKeystream *Clone() const = 0;
		virtual void SetKey(const uint8_t *key, size_t sz) = 0;
		virtual void SetNonce(const uint8_t *key, size_t sz) = 0;
		virtual void Reset() = 0;
		virtual void FillBuffer(uint8_t *) = 0;
		virtual void FillBufferAligned(uint8_t *) = 0;
		virtual void SetRounds(size_t rounds)
		{
			nrounds = rounds;
		}
		size_t GetKeySize() const
		{
			return keysz;
		}
	protected:
		size_t keysz;
		size_t nrounds;
};

class Salsa20Keystream : public Salsa20GenericKeystream
{
	public:
		Salsa20Keystream();
		~Salsa20Keystream() {}
		Salsa20GenericKeystream *Clone() const
		{
			return new Salsa20Keystream(*this);
		}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void Reset();
		void FillBuffer(uint8_t *);
		void FillBufferAligned(uint8_t *);
		void SetRounds(size_t rounds);
	protected:
	private:
		struct AlignedData
		{
			uint32_t buf[16] ALIGNED_T;
		};
		virtual void DoHash(AlignedData &cur);
		AlignedData state;
		uint64_t ctr;
};

#ifdef SALSA_HAVE_ASM
class Salsa20AssemblerKeystream : public Salsa20GenericKeystream
{
	public:
		struct AlignedData
		{
			uint32_t buf[16] ALIGNED_T;
		};
		Salsa20AssemblerKeystream();
		~Salsa20AssemblerKeystream() {}
		Salsa20GenericKeystream *Clone() const
		{
			return new Salsa20AssemblerKeystream(*this);
		}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void Reset();
		void FillBuffer(uint8_t *);
		void FillBufferAligned(uint8_t *);
	protected:
	private:
		AlignedData state;
};
#endif

class Salsa20
{
	public:
		Salsa20();
		Salsa20(Salsa20GenericKeystream *ks);
		Salsa20(size_t);
		Salsa20(Salsa20GenericKeystream *ks, size_t);
		Salsa20(const Salsa20 &other)
		{
			m_ks = other.m_ks->Clone();
		}
		~Salsa20()
		{
			delete m_ks;
		}
		void Reset();
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
		void EncryptFast(uint8_t *out, const uint8_t *in, size_t len);
		size_t GetKeySize() const
		{
			return m_ks->GetKeySize();
		}
	protected:
	private:
		Salsa20GenericKeystream *m_ks;
		uint8_t m_buf[64] ALIGNED_T;
		size_t m_nbytes;
};

}
UNHIDE()

#endif
