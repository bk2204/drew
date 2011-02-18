#ifndef SALSA20_HH
#define SALSA20_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

namespace drew {

class Salsa20Keystream
{
	public:
		typedef LittleEndian endian_t;
		Salsa20Keystream();
		~Salsa20Keystream() {}
		void SetKey(const uint8_t *key, size_t sz);
		void SetNonce(const uint8_t *key, size_t sz);
		void Reset();
		void GetValue(uint8_t *);
#ifdef DREW_TEST
		static int Test();
#endif
	protected:
	private:
		static void DoHash(uint32_t *cur, const uint32_t *st);
		static void DoQuarterRound(uint32_t &, uint32_t &, uint32_t &,
				uint32_t &);
		static void DoRowRound(uint32_t *);
		static void DoColumnRound(uint32_t *);
		static void DoDoubleRound(uint32_t *);
#ifdef DREW_TEST
		static int TestQuarterRound();
		static int TestRowRound();
		static int TestColumnRound();
		static int TestDoubleRound();
		static int TestHash();
#endif
		uint32_t state[16];
		size_t keysz;
		uint64_t ctr;
};

class Salsa20
{
	public:
		Salsa20();
		~Salsa20() {}
		void SetNonce(const uint8_t *, size_t sz);
		void SetKey(const uint8_t *key, size_t sz);
		void Encrypt(uint8_t *out, const uint8_t *in, size_t len);
		void Decrypt(uint8_t *out, const uint8_t *in, size_t len);
	protected:
	private:
		Salsa20Keystream m_ks;
		uint8_t m_buf[64];
		size_t m_nbytes;
};

}

#endif
