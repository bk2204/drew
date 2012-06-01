/*-
 * Copyright © 2012 brian m. carlson
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
#ifndef JH_HH
#define JH_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class JH : public Hash<uint64_t, 64, 128, 64, LittleEndian>
{
	public:
		JH(size_t sz);
		virtual ~JH() {}
		void Reset();
		virtual void GetDigest(uint8_t *digest, size_t len, bool nopad);
		virtual size_t GetDigestSize() const
		{
			return m_size;
		}
		virtual void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			JH::Transform(m_hash, data);
		}
		static void Transform(uint64_t *, const uint8_t *);
		size_t m_size;
	private:
};

}
UNHIDE()

#endif
