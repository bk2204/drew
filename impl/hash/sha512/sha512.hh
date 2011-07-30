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
#ifndef SHA512_HH
#define SHA512_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class SHA512Transform
{
	public:
		typedef BigEndian endian;
		virtual ~SHA512Transform() {}
		static void Transform(uint64_t *state, const uint8_t *data);
};

class SHA512 : public Hash<uint64_t, 64, 64, 128, BigEndian>,
	public SHA512Transform
{
	public:
		SHA512();
		virtual ~SHA512() {}
		virtual void Reset();
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			SHA512Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class SHA512t : public SHA512
{
	public:
		SHA512t(size_t);
		virtual ~SHA512t() {}
		void Reset();
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			SHA512Transform::Transform(state, data);
		}
		void GetDigest(uint8_t *digest, bool nopad)
		{
			if (!nopad)
				Pad();

			endian_t::Copy(digest, m_hash, t);
		}
		size_t GetDigestSize() const
		{
			return t;
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
		size_t t;
	private:
};

class SHA384 : public Hash<uint64_t, 48, 64, 128, BigEndian>,
	public SHA512Transform
{
	public:
		SHA384();
		virtual ~SHA384() {}
		void Reset();
		static void Transform(uint64_t *state, const uint8_t *data)
		{
			SHA512Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

}
UNHIDE()

#endif
