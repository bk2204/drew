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
#include "tea.hh"
#include "btestcase.hh"

HIDE()
extern "C" {

static const int teakeysz[] =
{
	16
};

static int teatest(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;

	res |= BlockTestCase<TEA>("00000000000000000000000000000000", 16).Test("0000000000000000",
			"41ea3a0a94baa940");
	res |= BlockTestCase<TEA>("00000000000000000000000041ea3a0a", 16).Test("94baa94000000000",
			"4e8e78297d8236d8");
	res |= BlockTestCase<TEA>("000000000000000041ea3a0a4e8e7829", 16).Test("7d8236d800000000",
			"c88ba95ee7edac02");
	res |= BlockTestCase<TEA>("0000000041ea3a0a4e8e7829c88ba95e", 16).Test("e7edac0200000000",
			"b84e28afb6b62088");
	res |= BlockTestCase<TEA>("41ea3a0a4e8e7829c88ba95eb84e28af", 16).Test("b6b6208800000000",
			"a0a472958fadf3b3");
	res |= BlockTestCase<TEA>("4e8e7829c88ba95eb84e28afa0a47295", 16).Test("8fadf3b341ea3a0a",
			"ed650698cf9f2b79");
	res |= BlockTestCase<TEA>("c88ba95eb84e28afa0a47295ed650698", 16).Test("cf9f2b794e8e7829",
			"1024eea06220ae1c");
	res |= BlockTestCase<TEA>("b84e28afa0a47295ed6506981024eea0", 16).Test("6220ae1cc88ba95e",
			"5ddf75d97a4ce68f");
	res <<= 2;
	res |= BlockTestCase<TEA>("a0a47295ed6506981024eea05ddf75d9", 16).Test("7a4ce68fb84e28af",
			"f1be9d1e8dd4a984");
	res |= BlockTestCase<TEA>("ed6506981024eea05ddf75d9f1be9d1e", 16).Test("8dd4a984a0a47295",
			"d32c758c092dabad");
	res |= BlockTestCase<TEA>("1024eea05ddf75d9f1be9d1ed32c758c", 16).Test("092dabaded650698",
			"bdb43728f7183fc0");
	res |= BlockTestCase<TEA>("5ddf75d9f1be9d1ed32c758cbdb43728", 16).Test("f7183fc01024eea0",
			"a9c3801ad9dcfb4e");
	res |= BlockTestCase<TEA>("f1be9d1ed32c758cbdb43728a9c3801a", 16).Test("d9dcfb4e5ddf75d9",
			"32a1e654a9df917c");
	res |= BlockTestCase<TEA>("d32c758cbdb43728a9c3801a32a1e654", 16).Test("a9df917cf1be9d1e",
			"08b63bb9b20bd3e8");
	res |= BlockTestCase<TEA>("bdb43728a9c3801a32a1e65408b63bb9", 16).Test("b20bd3e8d32c758c",
			"21410574cc4264c6");
	res |= BlockTestCase<TEA>("a9c3801a32a1e65408b63bb921410574", 16).Test("cc4264c6bdb43728",
			"4ec5d2e25ada1d89");
	res <<= 2;
	res |= BlockTestCase<TEA>("32a1e65408b63bb9214105744ec5d2e2", 16).Test("5ada1d89a9c3801a",
			"dd46249e28aa0b4b");
	res |= BlockTestCase<TEA>("08b63bb9214105744ec5d2e2dd46249e", 16).Test("28aa0b4b32a1e654",
			"2486dcbaa713df03");
	res |= BlockTestCase<TEA>("214105744ec5d2e2dd46249e2486dcba", 16).Test("a713df0308b63bb9",
			"b7c7af9d1acb6cab");
	res |= BlockTestCase<TEA>("4ec5d2e2dd46249e2486dcbab7c7af9d", 16).Test("1acb6cab21410574",
			"8cc0400a9aa49fbb");
	res |= BlockTestCase<TEA>("dd46249e2486dcbab7c7af9d8cc0400a", 16).Test("9aa49fbb4ec5d2e2",
			"9c2418766cbc8c66");
	res |= BlockTestCase<TEA>("2486dcbab7c7af9d8cc0400a9c241876", 16).Test("6cbc8c66dd46249e",
			"b59c5d45a90066f9");
	res |= BlockTestCase<TEA>("b7c7af9d8cc0400a9c241876b59c5d45", 16).Test("a90066f92486dcba",
			"b765a1b364b37eb0");
	res |= BlockTestCase<TEA>("8cc0400a9c241876b59c5d45b765a1b3", 16).Test("64b37eb0b7c7af9d",
			"7b172facf5ab4933");
	res <<= 2;
	res |= BlockTestCase<TEA>("9c241876b59c5d45b765a1b37b172fac", 16).Test("f5ab49338cc0400a",
			"fe48f4fbada404b1");
	res |= BlockTestCase<TEA>("b59c5d45b765a1b37b172facfe48f4fb", 16).Test("ada404b19c241876",
			"c5294093c1d53e3d");
	res |= BlockTestCase<TEA>("b765a1b37b172facfe48f4fbc5294093", 16).Test("c1d53e3db59c5d45",
			"759ca8e277a96649");
	res |= BlockTestCase<TEA>("7b172facfe48f4fbc5294093759ca8e2", 16).Test("77a96649b765a1b3",
			"69c53e0f3e979807");
	res |= BlockTestCase<TEA>("fe48f4fbc5294093759ca8e269c53e0f", 16).Test("3e9798077b172fac",
			"60388adaa21fa8e8");
	res |= BlockTestCase<TEA>("c5294093759ca8e269c53e0f60388ada", 16).Test("a21fa8e8fe48f4fb",
			"df70a1f5ac4aa407");
	res |= BlockTestCase<TEA>("759ca8e269c53e0f60388adadf70a1f5", 16).Test("ac4aa407c5294093",
			"d9cb4e0992636233");
	res |= BlockTestCase<TEA>("69c53e0f60388adadf70a1f5d9cb4e09", 16).Test("92636233759ca8e2",
			"7d2c6c577a6adb4d");
	res <<= 2;
	res |= BlockTestCase<TEA>("60388adadf70a1f5d9cb4e097d2c6c57", 16).Test("7a6adb4d69c53e0f",
			"44b71215cf25368a");
	res |= BlockTestCase<TEA>("df70a1f5d9cb4e097d2c6c5744b71215", 16).Test("cf25368a60388ada",
			"c10105a1ef781a18");
	res |= BlockTestCase<TEA>("d9cb4e097d2c6c5744b71215c10105a1", 16).Test("ef781a18df70a1f5",
			"bfdb29fa9ece39b6");
	res |= BlockTestCase<TEA>("7d2c6c5744b71215c10105a1bfdb29fa", 16).Test("9ece39b6d9cb4e09",
			"9b0b256ddc04574c");
	res |= BlockTestCase<TEA>("44b71215c10105a1bfdb29fa9b0b256d", 16).Test("dc04574c7d2c6c57",
			"f82951428c022711");
	res |= BlockTestCase<TEA>("c10105a1bfdb29fa9b0b256df8295142", 16).Test("8c02271144b71215",
			"61341d1c3a85f2f0");
	res |= BlockTestCase<TEA>("bfdb29fa9b0b256df829514261341d1c", 16).Test("3a85f2f0c10105a1",
			"f6a0d30cad230209");
	res |= BlockTestCase<TEA>("9b0b256df829514261341d1cf6a0d30c", 16).Test("ad230209bfdb29fa",
			"3de21a3faa0cf5c9");
	res <<= 2;
	res |= BlockTestCase<TEA>("f829514261341d1cf6a0d30c3de21a3f", 16).Test("aa0cf5c99b0b256d",
			"a7e307c6bd52d939");
	res |= BlockTestCase<TEA>("61341d1cf6a0d30c3de21a3fa7e307c6", 16).Test("bd52d939f8295142",
			"017bc3a766fd8c77");
	res |= BlockTestCase<TEA>("f6a0d30c3de21a3fa7e307c6017bc3a7", 16).Test("66fd8c7761341d1c",
			"d8f8fc86d01b5761");
	res |= BlockTestCase<TEA>("3de21a3fa7e307c6017bc3a7d8f8fc86", 16).Test("d01b5761f6a0d30c",
			"e186c41a5e6e5a4d");
	res |= BlockTestCase<TEA>("a7e307c6017bc3a7d8f8fc86e186c41a", 16).Test("5e6e5a4d3de21a3f",
			"4368d224dbb4e677");
	res |= BlockTestCase<TEA>("017bc3a7d8f8fc86e186c41a4368d224", 16).Test("dbb4e677a7e307c6",
			"9bd0321e84096523");
	res |= BlockTestCase<TEA>("d8f8fc86e186c41a4368d2249bd0321e", 16).Test("84096523017bc3a7",
			"b7c56d5b97c65866");
	res |= BlockTestCase<TEA>("e186c41a4368d2249bd0321eb7c56d5b", 16).Test("97c65866d8f8fc86",
			"63a1bfac5a5d7ca2");
	res <<= 2;
	res |= BlockTestCase<TEA>("4368d2249bd0321eb7c56d5b63a1bfac", 16).Test("5a5d7ca2e186c41a",
			"91f56dff7281794f");
	res |= BlockTestCase<TEA>("9bd0321eb7c56d5b63a1bfac91f56dff", 16).Test("7281794f4368d224",
			"e4c63780019aedf7");
	res |= BlockTestCase<TEA>("b7c56d5b63a1bfac91f56dffe4c63780", 16).Test("019aedf79bd0321e",
			"a9fb56e735f4aeca");
	res |= BlockTestCase<TEA>("63a1bfac91f56dffe4c63780a9fb56e7", 16).Test("35f4aecab7c56d5b",
			"a6537187f0f1ba93");
	res |= BlockTestCase<TEA>("91f56dffe4c63780a9fb56e7a6537187", 16).Test("f0f1ba9363a1bfac",
			"cc960edae44c6b8f");
	res |= BlockTestCase<TEA>("e4c63780a9fb56e7a6537187cc960eda", 16).Test("e44c6b8f91f56dff",
			"e12f106d4f1152d0");
	res |= BlockTestCase<TEA>("a9fb56e7a6537187cc960edae12f106d", 16).Test("4f1152d0e4c63780",
			"556ad853f79992fd");
	res |= BlockTestCase<TEA>("a6537187cc960edae12f106d556ad853", 16).Test("f79992fda9fb56e7",
			"78e8e265128df6ad");
	res <<= 2;
	res |= BlockTestCase<TEA>("cc960edae12f106d556ad85378e8e265", 16).Test("128df6ada6537187",
			"f23892aa288cb926");
	res |= BlockTestCase<TEA>("e12f106d556ad85378e8e265f23892aa", 16).Test("288cb926cc960eda",
			"1d1158396a117fca");
	res |= BlockTestCase<TEA>("556ad85378e8e265f23892aa1d115839", 16).Test("6a117fcae12f106d",
			"cf8996355b087e34");
	res |= BlockTestCase<TEA>("78e8e265f23892aa1d115839cf899635", 16).Test("5b087e34556ad853",
			"5c60bff2e68d88c2");
	res |= BlockTestCase<TEA>("f23892aa1d115839cf8996355c60bff2", 16).Test("e68d88c278e8e265",
			"7072d01cbffeb50a");
	res |= BlockTestCase<TEA>("1d115839cf8996355c60bff27072d01c", 16).Test("bffeb50af23892aa",
			"4513c5eb9c99ae9e");
	res |= BlockTestCase<TEA>("cf8996355c60bff27072d01c4513c5eb", 16).Test("9c99ae9e1d115839",
			"8f3a38ab80d9c4ad");
	res |= BlockTestCase<TEA>("5c60bff27072d01c4513c5eb8f3a38ab", 16).Test("80d9c4adcf899635",
			"2bb0f1b3c023ed11");

	return res;
}

	PLUGIN_STRUCTURE(tea, TEA)
	PLUGIN_DATA_START()
	PLUGIN_DATA(tea, "TEA")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(tea)
}

typedef drew::TEA::endian_t E;

drew::TEA::TEA()
{
}

int drew::TEA::SetKey(const uint8_t *key, size_t len)
{
	E::Copy(m_k, key, len);
	return 0;
}

int drew::TEA::Encrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t v[2];

	E::Copy(v, in, sizeof(v));

	const uint32_t delta = 0x9e3779b9;
	uint32_t sum = 0;

	for (size_t i = 0; i < 32; i += 2) {
		sum += delta;
		v[0] += ((v[1] << 4) + m_k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + m_k[1]);
		v[1] += ((v[0] << 4) + m_k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + m_k[3]);

		sum += delta;
		v[0] += ((v[1] << 4) + m_k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + m_k[1]);
		v[1] += ((v[0] << 4) + m_k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + m_k[3]);
	}

	E::Copy(out, v, sizeof(v));
	return 0;
}

int drew::TEA::Decrypt(uint8_t *out, const uint8_t *in) const
{
	uint32_t v[2];

	E::Copy(v, in, sizeof(v));

	const uint32_t delta = 0x9e3779b9;
	uint32_t sum = delta << 5;

	for (size_t i = 0; i < 32; i += 2) {
		v[1] -= ((v[0] << 4) + m_k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + m_k[3]);
		v[0] -= ((v[1] << 4) + m_k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + m_k[1]);
		sum -= delta;

		v[1] -= ((v[0] << 4) + m_k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + m_k[3]);
		v[0] -= ((v[1] << 4) + m_k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + m_k[1]);
		sum -= delta;
	}

	E::Copy(out, v, sizeof(v));
	return 0;
}
UNHIDE()
