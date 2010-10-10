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

			StringToBytes(buf, str, len/2);
			return Test(buf, sizeof(buf));
		}
		static int MaintenanceTest(const char *str)
		{
			uint8_t *output = StringToBytes(str, strlen(str)/2);
			if (!output)
				return 0xe;
			int res = MaintenanceTest(output);
			delete[] output;
			return res;

		}
#define NBYTEVALS 256
		static int MaintenanceTest(const uint8_t *output)
		{
			int res = 0;
			T context;
			uint8_t buf[NBYTEVALS][256];
			T *ctxt = new T[NBYTEVALS];

			for (size_t i = 0; i < NBYTEVALS; i++) {
				memset(buf[i], (uint8_t)i, 256);
				ctxt[i].Update(buf[i], i);
			}

			for (size_t i = 0; i < 50000; i++) {
				const uint8_t imod = i;
				uint8_t md[T::digest_size];

				T clone(ctxt[imod]);
				clone.GetDigest(md, false);
				context.Update(md, T::digest_size);
				ctxt[imod].Update(buf[imod], 256);
			}
			uint8_t md[T::digest_size];
			context.GetDigest(md, false);

			res = !!memcmp(md, output, T::digest_size);

			delete[] ctxt;

			return res;
		}
	protected:
		static uint8_t *StringToBytes(const char *str, size_t len)
		{
			uint8_t *buf = new uint8_t[len];
			if (!StringToBytes(buf, str, len)) {
				delete[] buf;
				return NULL;
			}
			return buf;
		}
		static bool StringToBytes(uint8_t *buf, const char *str, size_t len)
		{
			for (size_t i = 0; i < len; i++) {
				unsigned int x;
				if (sscanf(str + (i*2), "%02x", &x) != 1)
					return false;
				buf[i] = x;
			}
			return true;
		}
	private:
		const uint8_t *m_buf;
		size_t m_len, m_reps;
		uint8_t m_result[T::digest_size];
};

}

#endif
