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
#ifndef CAST_HH
#define CAST_HH

#include <stddef.h>
#include <stdint.h>

#include "util.hh"

HIDE()
namespace drew {

class CAST
{
	public:
	protected:
#define item(x) (m_s[x][EndianBase::GetByte(val, 3-x)])
		inline uint32_t f1(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km + x, kr);

			return ((item(0) ^ item(1)) - item(2)) + item(3);
		}

		inline uint32_t f2(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km ^ x, kr);

			return ((item(0) - item(1)) + item(2)) ^ item(3);
		}

		inline uint32_t f3(uint32_t x, uint32_t km, uint8_t kr) const
		{
			const uint32_t val = RotateLeft(km - x, kr);

			return ((item(0) + item(1)) ^ item(2)) - item(3);
		}
		static const uint32_t m_s[8][256];
	private:
};

}
UNHIDE()

#endif
