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
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.h"
#include "block-plugin.hh"
#include "btestcase.hh"
#include "serpent.hh"

HIDE()
extern "C" {

static const int serpentkeysz[] =
{
	16, 24, 32
};

static int serpent128_test(void)
{
	using namespace drew;
	int res = 0;
	const char *key = "00000000000000000000000000000000";
	res |= BlockTestCase<Serpent>(key).Test("00000000000000000000000000000080",
			"4ae9a20b2b14a10290cbb820b7ffb510");
	res <<= 2;
	res |= BlockTestCase<Serpent>::MaintenanceTest(
			"d492845d935c050de90d43e32e5277a1"
			"a63d61a06fc0a54269a012038ad2fd12"
			"b97905d4a9af7c9477bf44f06ef21948"
			"f5325c2271bcac0dfce258e7c2c5bae9", 16, 16);
	return res;
}

static int serpent_big_test(void)
{
	using namespace drew;

	int res = 0;
	const char *key = "00000000000000000000000000000000"
		"00000000000000000000000000000000";

	res |= BlockTestCase<Serpent>(key, 24).Test(
			"d29d576fceaba3a7ed9899f2927bd78e",
			"130e353e1037c22405e8faefb2c3c3e9", 16);
	res <<= 2;
	res |= BlockTestCase<Serpent>(key, 32).Test(
			"d095576fcea3e3a7ed98d9f29073d78e",
			"b90ee5862de69168f2bdd5125b45472b", 16);
	res <<= 2;
	res |= BlockTestCase<Serpent>::MaintenanceTest(
			"6a60355cac8f2ed762ccc6ca12cf918e"
			"08cb9ecf3d24e7825b8145754cc00b40"
			"f59cae607af42dfad1033510f9966502"
			"10a75e387cd44ce9f8f82bac7e731d0e", 24, 16);
	res <<= 2;
	res |= BlockTestCase<Serpent>::MaintenanceTest(
			"80824ce899c98fcef5b7992193602930"
			"7e78311ba9d3dafd8ddabcfc938293ec"
			"88941ec0f3816fea9cde78a645f2df1d"
			"4dabb9223a30a5dd3f0fc054d46c5938", 32, 16);

	return res;
}

static int serpenttest(void *, const drew_loader_t *)
{
	int res = 0;

	res |= serpent128_test();
	res <<= 4;
	res |= serpent_big_test();

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(serpent, Serpent)
	PLUGIN_DATA_START()
	PLUGIN_DATA(serpent, "Serpent")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(serpent)
}
UNHIDE()
