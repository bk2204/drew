/*-
 * Copyright © 2010–2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#ifndef HASH_TESTCASE_HH
#define HASH_TESTCASE_HH

#include <stdint.h>
#include <string.h>

#include <sstream>

namespace drew {

template<class T, unsigned N>
struct HashInstantiator
{
	static T *CreateInstance()
	{
		return new T;
	}
};

template<class T, unsigned N>
struct VariableSizedHashInstantiator
{
	static T *CreateInstance()
	{
		return new T(N);
	}
};

template<class T, unsigned N = T::digest_size,
	class I = HashInstantiator<T, N> >
class HashTestCase
{
	public:
		HashTestCase(const uint8_t *buf, size_t len, size_t reps)
		{
			Initialize(buf, len, reps);
		}
		HashTestCase(const char *buf, size_t reps)
		{
			Initialize(reinterpret_cast<const uint8_t *>(buf), strlen(buf),
					reps);
		}
		virtual ~HashTestCase() {};
		bool Test(const uint8_t *buf, size_t len)
		{
			if (len != N)
				return false;

			T *hash = CreateInstance();
			for (size_t i = 0; i < m_reps; i++)
				hash->Update(m_buf, m_len);
			hash->GetDigest(m_result, hash->GetDigestSize(), 0);

			int result = !memcmp(buf, m_result, N);
			delete hash;
			return result;
		}
		bool Test(const char *str)
		{
			uint8_t buf[N];
			const size_t len = strlen(str);

			if (len != (N * 2))
				return false;

			StringToBytes(buf, str, len/2);
			return Test(buf, sizeof(buf));
		}
		static bool MaintenanceTest(const char *str)
		{
			uint8_t *output = StringToBytes(str, strlen(str)/2);
			if (!output)
				return false;
			bool res = MaintenanceTest(output);
			delete[] output;
			return res;

		}
#define NBYTEVALS 256
		static bool MaintenanceTest(const uint8_t *output)
		{
			T *context = CreateInstance();
			uint8_t buf[NBYTEVALS][256];
			T *ctxt[NBYTEVALS];

			for (size_t i = 0; i < NBYTEVALS; i++) {
				memset(buf[i], (uint8_t)i, 256);
				ctxt[i] = CreateInstance();
				ctxt[i]->Update(buf[i], i);
			}

			for (size_t i = 0; i < 50000; i++) {
				const uint8_t imod = i;
				uint8_t md[N];

				T clone(*ctxt[imod]);
				clone.GetDigest(md, clone.GetDigestSize(), false);
				context->Update(md, N);
				ctxt[imod]->Update(buf[imod], 256);
			}
			for (size_t i = 0; i < NBYTEVALS; i++)
				delete ctxt[i];
			uint8_t md[N];
			context->GetDigest(md, context->GetDigestSize(), false);
			delete context;

			bool res = !memcmp(md, output, N);

			return res;
		}
	protected:
		HashTestCase() {}
		static T * CreateInstance()
		{
			return I::CreateInstance();
		}
		void Initialize(const uint8_t *buf, size_t len, size_t reps)
		{
			m_buf = buf;
			m_len = len;
			m_reps = reps;
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
		const uint8_t *m_buf;
		size_t m_len, m_reps;
		uint8_t m_result[N];
};

template<class T, unsigned N>
class VariableSizedHashTestCase :
	public HashTestCase<T, N, VariableSizedHashInstantiator<T, N> >
{
	public:
		VariableSizedHashTestCase(const uint8_t *buf, size_t len, size_t reps)
		{
			this->Initialize(buf, len, reps);
		}
		VariableSizedHashTestCase(const char *buf, size_t reps)
		{
			this->Initialize(reinterpret_cast<const uint8_t *>(buf),
					strlen(buf), reps);
		}
		virtual ~VariableSizedHashTestCase() {};
};

}

#endif
