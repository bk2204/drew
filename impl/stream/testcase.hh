#ifndef HASH_TESTCASE_HH
#define HASH_TESTCASE_HH

#include <stdint.h>
#include <string.h>

#include <sstream>

namespace drew {

template<class T>
class StreamTestCase
{
	public:
		StreamTestCase(const uint8_t *buf, size_t len) :
			m_key(buf), m_abuf(0), m_keysz(len)
		{
		}
		StreamTestCase(const char *buf, size_t len = 0) :
			m_keysz(len)
		{
			if (!m_keysz)
				m_keysz = strlen(buf) / 2;
			m_key = m_abuf = new uint8_t[m_keysz];
			StringToBytes(m_abuf, buf, m_keysz);
		}
		~StreamTestCase()
		{
			if (m_abuf)
				delete[] m_abuf;
		}
		int Test(const uint8_t *pt, const uint8_t *ct, size_t len, const uint8_t *nonce = 0, size_t noncelen = 0)
		{
			uint8_t *buf = new uint8_t[len];
			T algo;
			int res = 0;

			algo.SetKey(m_key, m_keysz);
			algo.Encrypt(buf, pt, len);
			if (memcmp(buf, ct, len))
				res |= 1;
#ifdef DREW_TESTCASE_DEBUG
			for (size_t i = 0; i < len; i++)
				printf("enc %02zu: %02x %02x %02x\n", i, pt[i], buf[i], ct[i]);
#endif
			algo.SetKey(m_key, m_keysz);
			algo.Decrypt(buf, ct, len);
			if (memcmp(buf, pt, len))
				res |= 2;
#ifdef DREW_TESTCASE_DEBUG
			for (size_t i = 0; i < len; i++)
				printf("dec %02zu: %02x %02x %02x\n", i, pt[i], buf[i], ct[i]);
#endif
			delete[] buf;

			return res;
		}
		int Test(const char *pt, const char *ct, size_t len = 0, const char *nonce = 0, size_t noncelen = 0)
		{
			if (!len)
				len = strlen(pt) / 2;
			if (nonce && !noncelen)
				noncelen = strlen(nonce) / 2;

			uint8_t *ptbuf = new uint8_t[len];
			uint8_t *ctbuf = new uint8_t[len];
			uint8_t *nobuf = NULL;
			if (nonce)
				nobuf = new uint8_t[noncelen];
			int res = 0;

			if (!StringToBytes(ptbuf, pt, len))
				res |= 4;
			if (!StringToBytes(ctbuf, ct, len))
				res |= 8;
			if (nonce && !StringToBytes(nobuf, nonce, noncelen))
				res |= 12;

			res |= Test(ptbuf, ctbuf, len, nobuf, noncelen);

			delete[] ptbuf;
			delete[] ctbuf;
			if (nonce)
				delete[] nobuf;

			return res;
		}
		static int MaintenanceTest(const char *str, size_t keysz, size_t noncesz = 0)
		{
			uint8_t *output = StringToBytes(str, strlen(str)/2);
			if (!output)
				return 0xe;
			int res = MaintenanceTest(output, keysz, noncesz);
			delete[] output;
			return res;

		}
		static int MaintenanceTest(const uint8_t *buf, size_t keysz,
				size_t noncesz = 0)
		{
			const char *str =
				"0123456712345678234567893456789a"
				"456789ab56789abc6789abcd789abcde"
				"89abcdef9abcdef0abcdef01bcdef012"
				"cdef0123def01234ef012345f0123456";
			uint8_t *input = StringToBytes(str, strlen(str)/2);
			if (!input)
				return 0xe;
			int res = MaintenanceTest(buf, input, strlen(str)/2, keysz, noncesz);
			delete[] input;
			return res;
		}
	protected:
		static int MaintenanceTest(const uint8_t *output, const uint8_t *input,
				size_t inputsz, size_t keysz, size_t noncesz)
		{
			int res = 0;
			T algo;
			const size_t blksz = 64;
			uint8_t *a = new uint8_t[blksz];
			uint8_t *b = new uint8_t[blksz];
			uint8_t *n = new uint8_t[blksz];

			for (size_t i = 0; i < inputsz; i++)
				a[i] = b[i] = n[i] = input[i % inputsz];
			for (size_t i = 0; i < 1000000; i++) {
				algo.SetKey(b, keysz);
				algo.SetNonce(n, noncesz);
				algo.Encrypt(a, a, blksz);
				algo.SetKey(a, keysz);
				algo.SetNonce(n, noncesz);
				algo.Encrypt(b, b, blksz);
			}

			res |= !!memcmp(output, a, blksz);
			res <<= 1;
			res |= !!memcmp(output+blksz, b, blksz);
			res <<= 1;

			for (size_t i = 0; i < 1000000; i++) {
				algo.SetKey(a, keysz);
				algo.SetNonce(n, noncesz);
				algo.Decrypt(b, b, blksz);
				algo.SetKey(b, keysz);
				algo.SetNonce(n, noncesz);
				algo.Decrypt(a, a, blksz);
			}
			res |= !!memcmp(a, b, blksz);
			res <<= 1;
			res |= !!memcmp(input, b, blksz);

			delete[] a;
			delete[] b;
			delete[] n;

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
