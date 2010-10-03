#ifndef HASH_TESTCASE_HH
#define HASH_TESTCASE_HH

#include <stdint.h>
#include <string.h>

#include <sstream>

namespace drew {

template<class T>
class BlockTestCase
{
	public:
		BlockTestCase(const uint8_t *buf, size_t len) :
			m_key(buf), m_abuf(0), m_keysz(len)
		{
		}
		BlockTestCase(const char *buf, size_t len = 0) :
			m_keysz(len)
		{
			if (!m_keysz)
				m_keysz = strlen(buf) / 2;
			m_key = m_abuf = new uint8_t[m_keysz];
			StringToBytes(m_abuf, buf, m_keysz);
		}
		~BlockTestCase()
		{
			if (m_abuf)
				delete[] m_abuf;
		}
		int Test(const uint8_t *pt, const uint8_t *ct, size_t len)
		{
			uint8_t *buf = new uint8_t[len];
			T algo;
			int res = 0;

			algo.SetKey(m_key, m_keysz);
			algo.Encrypt(buf, pt);
			if (memcmp(buf, ct, len))
				res |= 1;
			algo.Decrypt(buf, ct);
			if (memcmp(buf, pt, len))
				res |= 2;
			delete[] buf;

			return res;
		}
		int Test(const char *pt, const char *ct, size_t len = 0)
		{
			if (!len)
				len = strlen(pt) / 2;

			uint8_t *ptbuf = new uint8_t[len];
			uint8_t *ctbuf = new uint8_t[len];
			int res;

			if (!StringToBytes(ptbuf, pt, len))
				res |= 4;
			if (!StringToBytes(ctbuf, ct, len))
				res |= 8;

			res |= Test(ptbuf, ctbuf, len);

			delete[] ptbuf;
			delete[] ctbuf;

			return res;
		}
	protected:
		bool StringToBytes(uint8_t *buf, const char *str, size_t len)
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
		const uint8_t *m_key;
		uint8_t *m_abuf;
		size_t m_keysz;
};

}

#endif
