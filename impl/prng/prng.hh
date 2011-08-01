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
#ifndef BMC_PRNG_HH
#define BMC_PRNG_HH

#include <internal.h>
#include "util.h"
#include <drew/prng.h>

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define RANDOM_DEVICE "/dev/urandom"

HIDE()
namespace drew {

class PRNG
{
	public:
		virtual ~PRNG() {}
		virtual int Initialize()
		{
			m_entropy.SetValue(0);
			return 0;
		}
		virtual int AddRandomData(const uint8_t *buf, size_t len,
				size_t entropy) = 0;
		virtual int GetBytes(uint8_t *buf, size_t nbytes) = 0;
		size_t GetEntropyAvailable() const
		{
			return m_entropy.GetValue();
		}
	protected:
		class Entropy
		{
			public:
				size_t GetValue() const
				{
					return ent;
				}
				Entropy &SetValue(size_t x)
				{
					ent = x;
					return *this;
				}
				Entropy &operator-=(size_t x)
				{
					ent = (x < ent) ? ent - x : 0;
					return *this;
				}
				Entropy &operator+=(size_t x)
				{
					ent += x;
					return *this;
				}
			protected:
			private:
				size_t ent;
		};
		virtual void Stir() = 0;
		Entropy m_entropy;
	private:
};

class BytePRNG : public virtual PRNG
{
	public:
		virtual int GetBytes(uint8_t *buf, size_t nbytes)
		{
			try {
				for (size_t i = 0; i < nbytes; i++)
					buf[i] = GetByte();
				return nbytes;
			}
			catch (int x) {
				return x;
			}
		}
	protected:
		virtual uint8_t GetByte() = 0;
};

class BlockPRNG : public virtual PRNG
{
};

// This class is for PRNGs that must be seeded before use.
class SeededPRNG : public virtual PRNG
{
	public:
		virtual int AddRandomData(const uint8_t *buf, size_t len,
				size_t entropy) = 0;
	protected:
	private:
};

// This class is for PRNGs that cannot be seeded.
class SeedlessPRNG : public virtual PRNG
{
	public:
		virtual int AddRandomData(const uint8_t *buf, size_t len,
				size_t entropy)
		{
			return -DREW_ERR_NOT_ALLOWED;
		}
	protected:
	private:
};

class DevURandom : public SeedlessPRNG, public BlockPRNG
{
	public:
		void GetBytes(uint8_t *buf, size_t nbytes)
		{
			int fd = open(RANDOM_DEVICE, O_RDONLY);
			read(fd, buf, nbytes);
			close(fd);
		}
		using SeedlessPRNG::AddRandomData;
	protected:
		void Stir() {}
};

}
UNHIDE()

#endif
