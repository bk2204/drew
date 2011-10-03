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
#ifndef WHIRLPOOL_HH
#define WHIRLPOOL_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class Whirlpool : public Hash<uint64_t, 64, 64, 64, BigEndian>
{
	public:
		Whirlpool();
		virtual ~Whirlpool() {}
		virtual void Reset();
		static void Transform(uint64_t *state, const uint8_t *data);
		void Pad();
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
		static const uint64_t C0[256], C1[256], C2[256], C3[256];
		static const uint64_t C4[256], C5[256], C6[256], C7[256];
		static const uint64_t rc[10];
		static void Round(uint64_t *res, const uint64_t *in);
	private:
};

}
UNHIDE()

#endif
