#ifndef RC4_HH
#define RC4_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

template<class T>
class RC4Keystream
{
	public:
		typedef T obj_t;
		RC4Keystream() {}
		~RC4Keystream() {}
		void SetKey(const uint8_t *key, size_t sz)
		{
			Reset();
			obj_t j = 0;
			for (size_t i = 0; i < 256; i++) {
				j += s[i] + key[i % sz];
				std::swap(s[i], s[uint8_t(j)]);
			}
		}
		void Reset()
		{
			for (size_t i = 0; i < 256; i++)
				s[i] = i;
			this->i = 0;
			this->j = 0;
		}
		obj_t GetValue()
		{
			i++;
			obj_t &x = s[uint8_t(i)];
			j += x;
			obj_t &y = s[uint8_t(j)];
			std::swap(x, y);
			return s[uint8_t(x + y)];
		}
	protected:
	private:
		obj_t s[256];
		obj_t i, j;

};

class RC4
{
	public:
		RC4();
		RC4(size_t drop);
		~RC4() {}
		inline void SetNonce(const uint8_t *, size_t sz) {}
		void Reset();
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		RC4Keystream<uint8_t> m_ks;
		size_t m_drop;
		uint8_t m_key[256];
		size_t m_sz;
};

}

#endif
