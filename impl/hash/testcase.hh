#ifndef HASH_TESTCASE_HH
#define HASH_TESTCASE_HH

#include <stdint.h>
#include <string.h>

#include <sstream>

namespace drew {

template<class T>
class HashTestCase
{
	public:
		HashTestCase(const uint8_t *buf, size_t len, size_t reps) :
			m_buf(buf), m_len(len), m_reps(reps)
		{
		}
		HashTestCase(const char *buf, size_t reps)
		{
			m_buf = reinterpret_cast<const uint8_t *>(buf);
			m_len = strlen(buf);
			m_reps = reps;
		}
		~HashTestCase() {};
		bool Test(const uint8_t *buf, size_t len)
		{
			if (len != T::digest_size)
				return false;

			T hash;
			for (size_t i = 0; i < m_reps; i++)
				hash.Update(m_buf, m_len);
			hash.GetDigest(m_result, 0);

			int result = !memcmp(buf, m_result, T::digest_size);
			return result;
		}
		bool Test(const char *str)
		{
			uint8_t buf[T::digest_size];
			const size_t len = strlen(str);

			if (len != (T::digest_size * 2))
				return false;

			for (size_t i = 0; i < len/2; i++) {
				unsigned int x;
				if (sscanf(str + (i*2), "%02x", &x) != 1)
					return false;
				buf[i] = x;
			}
			return Test(buf, sizeof(buf));
		}
	protected:
	private:
		const uint8_t *m_buf;
		size_t m_len, m_reps;
		uint8_t m_result[T::digest_size];
};

}

#endif
