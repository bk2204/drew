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
#ifndef SHA256_HH
#define SHA256_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class SHA256Transform
{
	public:
		typedef BigEndian endian;
		virtual ~SHA256Transform() {}
		static void Transform(uint32_t *state, const uint8_t *data);
};

class SHA256 : public Hash<uint32_t, 32, 32, 64, BigEndian>,
	public SHA256Transform
{
	public:
		SHA256();
		virtual ~SHA256() {}
		void Reset();
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			SHA256Transform::Transform(state, data);
		}
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
};

class SHA224 : public Hash<uint32_t, 28, 32, 64, BigEndian>,
	public SHA256Transform
{
	public:
		SHA224();
		virtual ~SHA224() {}
		void Reset();
		static void Transform(uint32_t *state, const uint8_t *data)
		{
			SHA256Transform::Transform(state, data);
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
