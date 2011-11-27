/*-
 * Copyright © 2011 brian m. carlson
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
#ifndef FUGUE_HH
#define FUGUE_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class Fugue256Transform
{
	public:
		typedef BigEndian endian;
		virtual ~Fugue256Transform() {}
		static void Transform(uint32_t *state, const uint8_t *data);
	protected:
		static void Pad(uint32_t *, uint8_t *, uint32_t *);
		static void Final(uint32_t *);
};

class Fugue256 : public Hash<uint32_t, 32, 120, 4, BigEndian>,
	public Fugue256Transform
{
	public:
		Fugue256();
		virtual ~Fugue256() {}
		void Reset();
		virtual void GetDigest(uint8_t *digest, size_t len, bool nopad);
		virtual void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Fugue256Transform::Transform(m_hash, data);
		}
	private:
};

class Fugue224 : public Hash<uint32_t, 28, 120, 4, BigEndian>,
	public Fugue256Transform
{
	public:
		Fugue224();
		virtual ~Fugue224() {}
		void Reset();
		virtual void GetDigest(uint8_t *digest, size_t len, bool nopad);
		virtual void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Fugue256Transform::Transform(m_hash, data);
		}
	private:
};

}
UNHIDE()

#endif
