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

class Tiger : public Hash<uint64_t, 24, 24, 64, LittleEndian>
{
	public:
		Tiger();
		virtual ~Tiger() {}
		void Reset();
		static void Transform(uint64_t *state, const uint8_t *data);
		void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
	private:
		static void Schedule(uint64_t *state);
		static void Pass(const uint64_t *x, uint64_t &a, uint64_t &b,
				uint64_t &c, const unsigned k);
		static void Round(uint64_t &a, uint64_t &b, uint64_t &c,
				const uint64_t x, const uint64_t k);
		static const uint64_t t1[], t2[], t3[], t4[];
};
}
UNHIDE()

#endif
