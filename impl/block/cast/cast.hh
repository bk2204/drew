#ifndef CAST_HH
#define CAST_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

HIDE()
namespace drew {

class CAST
{
	public:
		typedef BigEndian endian_t;
	protected:
#define item(x) (m_s[x][endian_t::GetByte(val, 3-x)])
		inline uint32_t f1(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km + x, kr);
		
			return ((item(0) ^ item(1)) - item(2)) + item(3);
		}
		
		inline uint32_t f2(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km ^ x, kr);
		
			return ((item(0) - item(1)) + item(2)) ^ item(3);
		}
		
		inline uint32_t f3(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km - x, kr);
		
			return ((item(0) + item(1)) ^ item(2)) - item(3);
		}
		static const uint32_t m_s[8][256];
	private:
};

}
UNHIDE()

#endif
