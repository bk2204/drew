#ifndef BLOCK_TESTCASE_HH
#define BLOCK_TESTCASE_HH

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
#ifdef DREW_TESTCASE_DEBUG
			for (size_t i = 0; i < len; i++)
				printf("enc %02zu: %02x %02x %02x\n", i, pt[i], buf[i], ct[i]);
#endif
			algo.Decrypt(buf, ct);
			if (memcmp(buf, pt, len))
				res |= 2;
#ifdef DREW_TESTCASE_DEBUG
			for (size_t i = 0; i < len; i++)
				printf("dec %02zu: %02x %02x %02x\n", i, pt[i], buf[i], ct[i]);
#endif
			delete[] buf;

			return res;
		}
		int Test(const char *pt, const char *ct, size_t len = 0)
		{
			if (!len)
				len = strlen(pt) / 2;

			uint8_t *ptbuf = new uint8_t[len];
			uint8_t *ctbuf = new uint8_t[len];
			int res = 0;

			if (!StringToBytes(ptbuf, pt, len))
				res |= 4;
			if (!StringToBytes(ctbuf, ct, len))
				res |= 8;

			res |= Test(ptbuf, ctbuf, len);

			delete[] ptbuf;
			delete[] ctbuf;

			return res;
		}
		static int MaintenanceTest(const char *str, size_t keysz, size_t blksz)
		{
			uint8_t *output = StringToBytes(str, strlen(str)/2);
			if (!output)
				return 0xe;
			int res = MaintenanceTest(output, keysz, blksz);
			delete[] output;
			return res;

		}
		static int MaintenanceTest(const uint8_t *buf, size_t keysz,
				size_t blksz)
		{
			const char *str =
				"0123456712345678234567893456789a"
				"456789ab56789abc6789abcd789abcde"
				"89abcdef9abcdef0abcdef01bcdef012"
				"cdef0123def01234ef012345f0123456";
			uint8_t *input = StringToBytes(str, strlen(str)/2);
			if (!input)
				return 0xe;
			int res = MaintenanceTest(buf, input, keysz, blksz);
			delete[] input;
			return res;
		}
	protected:
		static int MaintenanceTest(const uint8_t *output, const uint8_t *input,
				size_t keysz, size_t blksz)
		{
			int res = 0;
			T algo;
			uint8_t *a = new uint8_t[blksz * 2];
			uint8_t *b = new uint8_t[blksz * 2];

			memcpy(a, input, blksz * 2);
			memcpy(b, input, blksz * 2);
			for (size_t i = 0; i < 1000000; i++) {
				algo.SetKey(b, keysz);
				algo.Encrypt(a, a);
				algo.Encrypt(a+blksz, a+blksz);
				algo.SetKey(a, keysz);
				algo.Encrypt(b, b);
				algo.Encrypt(b+blksz, b+blksz);
			}

			res |= !!memcmp(output, a, blksz * 2);
			res <<= 1;
			res |= !!memcmp(output+(blksz*2), b, blksz * 2);
			res <<= 1;

			for (size_t i = 0; i < 1000000; i++) {
				algo.SetKey(a, keysz);
				algo.Decrypt(b+blksz, b+blksz);
				algo.Decrypt(b, b);
				algo.SetKey(b, keysz);
				algo.Decrypt(a+blksz, a+blksz);
				algo.Decrypt(a, a);
			}
			res |= !!memcmp(a, b, blksz * 2);
			res <<= 1;
			res |= !!memcmp(input, b, blksz * 2);

			delete[] a;
			delete[] b;

			return res;
		}
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
		const uint8_t *m_key;
		uint8_t *m_abuf;
		size_t m_keysz;
};

}

#endif
