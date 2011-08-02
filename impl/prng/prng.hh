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
#include "util.hh"
#include <drew/prng.h>

#include <errno.h>
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

class SystemPRNG : public SeedlessPRNG, public BlockPRNG
{
	public:
		virtual int GetBytes(uint8_t *buf, size_t nbytes) = 0;
		virtual int CheckImplementation() = 0;
};

class RandomDevice : public SystemPRNG
{
	public:
		virtual int GetBytes(uint8_t *buf, size_t nbytes)
		{
			ssize_t sz;
			if (!filename)
				return -DREW_ERR_NOT_IMPL;
			int fd = open(filename, O_RDONLY), err = 0;
			if (fd < 0)
				return -errno;
			sz = read(fd, buf, nbytes);
			err = -errno;
			close(fd);
			return sz < 0 ? err : sz;
		}
		virtual int CheckImplementation()
		{
			if (!filename)
				return -DREW_ERR_NOT_IMPL;
			int fd = open(filename, O_RDONLY);
			if (fd < 0) {
				if (errno == ENOENT)
					return -DREW_ERR_NOT_IMPL;
				else
					return -errno;
			}
			close(fd);
			return 0;
		}
		using SeedlessPRNG::AddRandomData;
	protected:
		RandomDevice() : filename(NULL) {}
		const char *filename;
		void Stir() {}
};

class DevURandom : public RandomDevice
{
	public:
		DevURandom() { filename = "/dev/urandom"; }
};

class DevRandom : public RandomDevice
{
	public:
		DevRandom()
		{
#ifdef __OpenBSD__
			filename = "/dev/srandom";
#else
			filename = "/dev/random";
#endif
		}
};

class DevHWRandom : public RandomDevice
{
	public:
		DevHWRandom()
		{
#ifdef __OpenBSD__
			filename = "/dev/random";
#elif __linux__
			filename = "/dev/hwrng";
#endif
		}
};

template<class T, class U>
class FallbackPRNG : public SystemPRNG
{
	public:
		virtual int GetBytes(uint8_t *buf, size_t nbytes)
		{
			int res = 0;
			if (tprng.CheckImplementation())
				return uprng.GetBytes(buf, nbytes);
			res = tprng.GetBytes(buf, nbytes);
			if (res < 0)
				return uprng.GetBytes(buf, nbytes);
			return res;
		}
		virtual int CheckImplementation()
		{
			int res = tprng.CheckImplementation();
			if (res)
				return uprng.CheckImplementation();
			return res;
		}
		using SeedlessPRNG::AddRandomData;
	private:
		T tprng;
		U uprng;
};

#ifdef __RDRND__
class RDRAND : public SystemPRNG
{
	public:
		static const size_t chunksz = sizeof(void *);
		int GetBytes(uint8_t *buf, size_t nbytes)
		{
			int total = 0;
			for (size_t i = 0; i < DivideAndRoundUp(nbytes, chunksz);
					i++, total += chunksz, buf += chunksz) {
				if (chunksz == 4) {
					uint32_t val32;
					if (!__builtin_ia32_rdrand32_step(&val32))
						break;
					memcpy(buf, &val32, std::min<size_t>(chunksz,
								nbytes - total));
				}
				else {
					unsigned long long val64;
					if (!__builtin_ia32_rdrand64_step(&val64))
						break;
					memcpy(buf, &val64, std::min<size_t>(chunksz,
								nbytes - total));
				}
			}
			if (size_t(total) > nbytes)
				total = nbytes;
			if (!total)
				return -DREW_ERR_FAILED;
			return total;
		}
		int CheckImplementation()
		{
			uint32_t a, b, c, d;
			GetCpuid(1, a, b, c, d);
			return c & 0x40000000 ? 0 : -DREW_ERR_NOT_IMPL;
		}
		using SeedlessPRNG::AddRandomData;
	protected:
		void Stir() {}
};
#endif
typedef DevURandom ReliablePRNG;


}
UNHIDE()

#endif
