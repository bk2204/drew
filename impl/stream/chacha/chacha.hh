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
#ifndef CHACHA_HH
#define CHACHA_HH

#include <stddef.h>
#include <stdint.h>

#include "chacha.h"
#include "util.hh"

HIDE()
namespace drew {

class ChaChaGenericKeystream
{
	public:
		typedef LittleEndian endian_t;
		ChaChaGenericKeystream() {}
		virtual ~ChaChaGenericKeystream() {}
		virtual ChaChaGenericKeystream *Clone() const = 0;
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
		size_t GetNonceSize() const
		{
			return noncesz;
		}
	protected:
		size_t keysz;
		size_t noncesz;
		size_t nrounds;
};

class ChaChaKeystream : public ChaChaGenericKeystream
{
	public:
		ChaChaKeystream();
		~ChaChaKeystream() {}
		ChaChaGenericKeystream *Clone() const
		{
			return new ChaChaKeystream(*this);
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
		inline void QuarterRound(AlignedData &, int, int, int, int);
		virtual void DoHash(AlignedData &cur);
		AlignedData state;
		uint64_t ctr;
};

#ifdef CHACHA_HAVE_ASM
class ChaChaAssemblerKeystream : public ChaChaGenericKeystream
{
	public:
		struct AlignedData
		{
			uint32_t buf[16] ALIGNED_T;
		};
		ChaChaAssemblerKeystream();
		~ChaChaAssemblerKeystream() {}
		ChaChaGenericKeystream *Clone() const
		{
			return new ChaChaAssemblerKeystream(*this);
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

class ChaCha
{
	public:
		ChaCha();
		ChaCha(ChaChaGenericKeystream *ks);
		ChaCha(size_t);
		ChaCha(ChaChaGenericKeystream *ks, size_t);
		ChaCha(const ChaCha &other)
		{
			m_ks = other.m_ks->Clone();
		}
		~ChaCha()
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
		size_t GetNonceSize() const
		{
			return m_ks->GetNonceSize();
		}
	protected:
	private:
		ChaChaGenericKeystream *m_ks;
		uint8_t m_buf[64] ALIGNED_T;
		size_t m_nbytes;
};

}
UNHIDE()

#endif
