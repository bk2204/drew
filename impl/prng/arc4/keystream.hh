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
#ifndef KEYSTREAM_HH
#define KEYSTREAM_HH

#include <sys/types.h>

#include "prng.hh"

HIDE()
namespace drew {

class KeystreamGenerator
{
	public:
		KeystreamGenerator(int index);
		~KeystreamGenerator();
		uint8_t GetByte();
		void Stir(const uint8_t *, uint8_t);
	protected:
		uint8_t m_i, m_j;
		uint8_t m_s[256];
		static const uint8_t rc2table[256], md2table[256], ariatable[256],
					 ariatable2[256];
	private:
};

}
UNHIDE()

#endif
