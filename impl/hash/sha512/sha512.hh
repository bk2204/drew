#ifndef SHA512_HH
#define SHA512_HH

#include "hash.hh"
#include "endian.hh"
#include <stdint.h>

namespace drew {

class SHA512Transform
{
	public:
		typedef BigEndian endian;
		virtual ~SHA512Transform() {}
		static void Transform(uint64_t *state, const uint8_t *data);
};

class SHA512 : public Hash<uint64_t, 64, 64, 128, BigEndian>,
	public SHA512Transform
{
	public:
		SHA512();
		virtual ~SHA512() {}
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			SHA512Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class SHA384 : public Hash<uint64_t, 48, 64, 128, BigEndian>,
	public SHA512Transform
{
	public:
		SHA384();
		virtual ~SHA384() {}
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			SHA512Transform::Transform(state, data);
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
