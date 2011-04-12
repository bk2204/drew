#ifndef BMC_PRNG_HH
#define BMC_PRNG_HH

#include <internal.h>
#include <drew/prng.h>

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define RANDOM_DEVICE "/dev/urandom"

namespace drew {

class PRNG
{
	public:
		virtual ~PRNG() {}
		virtual void Initialize()
		{
			m_entropy.SetValue(0);
		}
		virtual int AddRandomData(const uint8_t *buf, size_t len,
				size_t entropy) = 0;
		virtual uint8_t GetByte() = 0;
		virtual void GetBytes(uint8_t *buf, size_t nbytes) = 0;
		virtual uint32_t GetInteger()
		{
			return ((GetByte() << 24) | (GetByte() << 16) | (GetByte() << 8) |
					GetByte());
		}
		uint32_t GetUniformInteger(uint32_t upper_bound)
		{
			uint32_t overage = (0xffffffff % upper_bound) + 1;
			uint32_t limit = 0xffffffff - overage;
			uint32_t retval;

			while ((retval = GetInteger()) > limit);
			
			return retval;
		}
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
		virtual void GetBytes(uint8_t *buf, size_t nbytes)
		{
			for (size_t i = 0; i < nbytes; i++)
				buf[i] = GetByte();
		}
};

class BlockPRNG : public virtual PRNG
{
	public:
		virtual uint8_t GetByte()
		{
			uint8_t b;
			GetBytes(&b, 1);
			return b;
		}
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

#endif
