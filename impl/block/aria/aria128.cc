#define ARIA_128
#include "aria.hh"

extern "C" {
static int ariatest(void *, const drew_loader_t *)
{
	using namespace drew;
	return test<ARIA128>(NULL, NULL);
}

	PLUGIN_STRUCTURE(aria, ARIA128)
	PLUGIN_DATA_START()
	PLUGIN_DATA(aria, "ARIA")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(aria128)
}

typedef drew::ARIA128::endian_t E;

drew::ARIA128::uint128_t drew::ARIA128::fo128(uint128_t a, uint128_t b) const
{
	AlignedData abuf, bbuf, cbuf, t;
	uint128_t c;

	E::Copy(t.data, &a, sizeof(t));
	Permute(abuf.data, t.data);
	E::Copy(t.data, &b, sizeof(t));
	Permute(bbuf.data, t.data);
	fo(cbuf, abuf, bbuf);
	Permute(t.data, cbuf.data);
	E::Copy(&c, t.data, sizeof(t));
	return c;
}

drew::ARIA128::uint128_t drew::ARIA128::fe128(uint128_t a, uint128_t b) const
{
	AlignedData abuf, bbuf, cbuf, t;
	uint128_t c;

	E::Copy(t.data, &a, sizeof(t));
	Permute(abuf.data, t.data);
	E::Copy(t.data, &b, sizeof(t));
	Permute(bbuf.data, t.data);
	fe(cbuf, abuf, bbuf);
	Permute(t.data, cbuf.data);
	E::Copy(&c, t.data, sizeof(t));
	return c;
}

int drew::ARIA128::SetKey(const uint8_t *key, size_t len)
{
	// There are only three constants, but they're repeated for convenience.
	static const uint128_t c[5] = {
		((uint128_t(0x517cc1b727220a94) << 64) | 0xfe13abe8fa9a6ee0),
		((uint128_t(0x6db14acc9e21c820) << 64) | 0xff28b1d5ef5de2b0),
		((uint128_t(0xdb92371d2126e970) << 64) | 0x0324977504e8c90e),
		((uint128_t(0x517cc1b727220a94) << 64) | 0xfe13abe8fa9a6ee0),
		((uint128_t(0x6db14acc9e21c820) << 64) | 0xff28b1d5ef5de2b0)
	};
	uint8_t buf[32] = {0};

	memcpy(buf, key, len);
	uint128_t kl, kr;

	E::Copy(&kl, buf+ 0, sizeof(kl));
	E::Copy(&kr, buf+16, sizeof(kr));

	size_t nrounds;

	switch (len / 8) {
		case 2:
			m_off = 0;
			nrounds = 12;
			break;
		case 3:
			m_off = 1;
			nrounds = 14;
			break;
		case 4:
			m_off = 2;
			nrounds = 16;
			break;
		default:
			return -DREW_ERR_INVALID;
	}

	const uint128_t *ck = c + m_off;
	uint128_t w[4];
	w[0] = kl;
	w[1] = fo128(w[0], ck[0]) ^ kr;
	w[2] = fe128(w[1], ck[1]) ^ w[0];
	w[3] = fo128(w[2], ck[2]) ^ w[1];

	uint128_t ek[17];
	static const size_t offsets[] = {19, 31, 67, 97};
	for (size_t i = 0, j = 0; i < 16; i += 4, j++) {
		ek[i + 0] = w[0] ^ RotateRight(w[1], offsets[j]);
		ek[i + 1] = w[1] ^ RotateRight(w[2], offsets[j]);
		ek[i + 2] = w[2] ^ RotateRight(w[3], offsets[j]);
		ek[i + 3] = w[3] ^ RotateRight(w[0], offsets[j]);
	}
	ek[16] = w[0] ^ RotateLeft(w[1], 19);

	for (size_t i = 0; i < 17; i++) {
		AlignedData d;
		E::Copy(d.data, &ek[i], 16);
		Permute(m_ek[i].data, d.data);
	}

	memcpy(m_dk[0].data, m_ek[nrounds].data, 16);
	for (size_t i = 1; i < nrounds; i++)
		afunc(m_dk[i], m_ek[nrounds - i]);
	memcpy(m_dk[nrounds].data, m_ek[0].data, 16);

	return 0;
}
