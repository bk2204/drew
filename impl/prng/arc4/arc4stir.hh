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
#ifndef ARC4STIR_HH
#define ARC4STIR_HH

#include <sys/types.h>

#include "prng.hh"
#include "keystream.hh"

HIDE()
namespace drew {

class ARC4Stir : public BytePRNG
{
	public:
		ARC4Stir();
		virtual ~ARC4Stir() {
			delete m_ks;
		}
		uint8_t GetByte();
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		void Stir();
		uint8_t InternalGetByte();
		void Stir(const uint8_t *);
		ssize_t m_cnt;
		KeystreamGenerator *m_ks;
	private:
};

}
UNHIDE()

#endif
