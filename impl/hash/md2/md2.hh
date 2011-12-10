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
#ifndef MD2_HH
#define MD2_HH

#include "hash.hh"
#include "util.hh"
#include <stdint.h>

HIDE()
namespace drew {

class MD2 : public Hash<uint8_t, 16, 64, 16, NonEndian>
{
	public:
		MD2();
		virtual ~MD2() {}
		void Reset();
		void Pad();
		static void Transform(quantum_t *state, const uint8_t *data);
	protected:
		virtual void Transform(const uint8_t *data)
		{
			Transform(m_hash, data);
		}
		static const uint8_t sbox[256];
		uint8_t *m_csum;
	private:
};

}
UNHIDE()

#endif
