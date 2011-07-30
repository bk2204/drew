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
#ifndef ARC4INTERLEAVE_HH
#define ARC4INTERLEAVE_HH

#include <sys/types.h>

#include "prng.hh"
#include "keystream.hh"

HIDE()
namespace drew {

class ARC4Interleave : public BytePRNG
{
	public:
		ARC4Interleave();
		virtual ~ARC4Interleave() {
			for (int i = 0; i < 4; i++)
				delete m_ks[i];
		}
		uint8_t GetByte();
		int AddRandomData(const uint8_t *buf, size_t len, size_t entropy);
	protected:
		uint8_t InternalGetByte();
		void Stir();
		ssize_t m_cnt;
		int m_index;
		KeystreamGenerator *m_ks[4];
	private:
};

}
UNHIDE()

#endif
