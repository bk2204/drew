#ifndef SHA256_HH
#define SHA256_HH

#include "hash.hh"
#include "endian.hh"
#include <stdint.h>

namespace drew {

class SHA256Transform
{
	public:
		typedef BigEndian endian;
		virtual ~SHA256Transform() {}
		static void Transform(uint32_t *state, const uint8_t *data);
};

class SHA256 : public Hash<uint32_t, 32, 32, 64, BigEndian>,
	public SHA256Transform
{
	public:
		SHA256();
		virtual ~SHA256() {}
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			SHA256Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class SHA224 : public Hash<uint32_t, 28, 32, 64, BigEndian>,
	public SHA256Transform
{
	public:
		SHA224();
		virtual ~SHA224() {}
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			SHA256Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

}

#endif
