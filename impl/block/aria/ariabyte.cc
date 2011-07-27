#define ARIA_BYTEWISE
#include "aria.hh"

HIDE()
extern "C" {
static int ariatest(void *, const drew_loader_t *)
{
	using namespace drew;
	return test<ARIABytewise>(NULL, NULL);
}

	PLUGIN_STRUCTURE(aria, ARIABytewise)
	PLUGIN_DATA_START()
	PLUGIN_DATA(aria, "ARIA")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(ariabyte)
}

typedef drew::ARIABytewise::endian_t E;

void drew::ARIABytewise::RotateRightAndXor(AlignedData &out,
		const AlignedData &in, const AlignedData &x, size_t offset) const
{
	const size_t nbytes = offset / 8;
	const size_t nbits = offset % 8;

	for (size_t i = 0; i < 16; i++)
		out.data[i] = (in.data[(i-nbytes) & 15] >> nbits) | 
			(in.data[(i-nbytes-1) & 15] << (8-nbits));
	XorAligned(out.data, out.data, x.data, 16);
}

int drew::ARIABytewise::SetKey(const uint8_t *key, size_t len)
{
	// There are only three constants, but they're repeated for convenience.
	static const AlignedData c[5] = {
		{{
			0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94,
			0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0
		}},
		{{
			0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20,
			0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0
		}},
		{{
			0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70,
			0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e
		}},
		{{
			0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94,
			0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0
		}},
		{{
			0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20,
			0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0
		}},
	};
	uint8_t buf[32] = {0};

	memcpy(buf, key, len);
	AlignedData kl, kr;

	memcpy(kl.data, buf+ 0, sizeof(kl));
	memcpy(kr.data, buf+16, sizeof(kr));

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

	const AlignedData *ck = c + m_off;
	AlignedData ckp[3];
	for (size_t i = 0; i < 3; i++)
		Permute(ckp[i].data, ck[i].data);
	AlignedData wp[4], krp;
	Permute(krp.data, kr.data);
	Permute(wp[0].data, kl.data);
	fo(wp[1], wp[0], ckp[0]);
	XorAligned(wp[1].data, wp[1].data, krp.data, 16);
	fe(wp[2], wp[1], ckp[1]);
	XorAligned(wp[2].data, wp[2].data, wp[0].data, 16);
	fo(wp[3], wp[2], ckp[2]);
	XorAligned(wp[3].data, wp[3].data, wp[1].data, 16);

	AlignedData w[4];
	for (size_t i = 0; i < 4; i++)
		Permute(w[i].data, wp[i].data);

	AlignedData ek[17];
	static const size_t offsets[] = {19, 31, 67, 97};
	for (size_t i = 0, j = 0; i < 16; i += 4, j++) {
		RotateRightAndXor(ek[i + 0], w[1], w[0], offsets[j]);
		RotateRightAndXor(ek[i + 1], w[2], w[1], offsets[j]);
		RotateRightAndXor(ek[i + 2], w[3], w[2], offsets[j]);
		RotateRightAndXor(ek[i + 3], w[0], w[3], offsets[j]);
	}
	RotateRightAndXor(ek[16], w[1], w[0], 109);

	for (size_t i = 0; i < 17; i++)
		Permute(m_ek[i].data, ek[i].data);

	memcpy(m_dk[0].data, m_ek[nrounds].data, 16);
	for (size_t i = 1; i < nrounds; i++)
		afunc(m_dk[i], m_ek[nrounds - i]);
	memcpy(m_dk[nrounds].data, m_ek[0].data, 16);

	return 0;
}
UNHIDE()
