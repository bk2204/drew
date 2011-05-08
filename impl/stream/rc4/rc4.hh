#ifndef RC4_HH
#define RC4_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class RC4Keystream
{
	public:
		// This can be set to int, which may be more advantageous on machines
		// that do not have byte-oriented registers (such as RISC machines).
		typedef uint8_t obj_t;
		RC4Keystream();
		~RC4Keystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void Reset();
		obj_t GetValue();
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
		RC4Keystream m_ks;
		size_t m_drop;
		uint8_t m_key[256];
		size_t m_sz;
};

}

#endif
