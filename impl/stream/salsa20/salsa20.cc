#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <plugin.h>
#include <stream.h>
#include "salsa20.hh"
#include "stream-plugin.h"
#include "testcase.hh"

extern "C" {

static int salsa20_maintenance_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<Salsa20>::MaintenanceTest("9bb285b4046d23d2afa572193"
			"95503a43940b5107670d26614b938c5d29a7ebbb5555be6a22ea75605078d974d"
			"c8e4e768e4ef612d32239afc8fb19a7508b5b5253708fc5f6e45f8fd72d5b317b"
			"89b1ab552eb337d4841cc37da6182610ed7848b596fcc5824a8330318f05013c7"
			"1f65094d67afeebc4286d976055d95a0397b", 16, 8);
	res <<= 4;
	res |= StreamTestCase<Salsa20>::MaintenanceTest("c183db6a97d3aa10045cd7847"
			"a7b43d581c11c2f82212481d44cb3fda40c70de2830a7b01a04c54d87afc93da9"
			"a6a0d4dd8b4b60dbf0773ab4f76b8c63b64205b4cc996aa2c1ba9c11b897d1630"
			"a3ad72285edb94ced28357587063054929515f9e795e9b82f66a22384724b06e3"
			"0203a05a107ec6379adf0409d1d917b17a47", 32, 8);

	return res;
}

static int salsa20_test(void *, drew_loader_t *)
{
	using namespace drew;

	int res = 0;
#ifdef DREW_TEST
	res |= Salsa20Keystream::Test();
	res <<= 16;
#endif
	res |= salsa20_maintenance_test();

	return res;
}

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static const int salsa_keysz[] = {16, 32};

static int salsa20_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 1;
		case DREW_STREAM_KEYSIZE:
			for (size_t i = 0; i < DIM(salsa_keysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (salsa_keysz[i] > *x)
					return salsa_keysz[i];
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::Salsa20);
		default:
			return -EINVAL;
	}
}

static int salsa20_init(void **ctx, void *data, int flags, drew_loader_t *, const drew_param_t *)
{
	drew::Salsa20 *p = new drew::Salsa20;
	if (flags & DREW_STREAM_INIT_FIXED) {
		memcpy(*ctx, p, sizeof(*p));
		delete p;
	}
	else
		*ctx = p;
	return 0;
}

static int salsa20_clone(void **newctx, void *oldctx, int flags)
{
	drew::Salsa20 *p =
		new drew::Salsa20(*reinterpret_cast<drew::Salsa20 *>(oldctx));
	if (flags & DREW_STREAM_CLONE_FIXED) {
		memcpy(*newctx, p, sizeof(*p));
		delete p;
	}
	else
		*newctx = p;
	return 0;
}

static int salsa20_setiv(void *ctx, const uint8_t *key, size_t len)
{
	drew::Salsa20 *p = reinterpret_cast<drew::Salsa20 *>(ctx);
	p->SetNonce(key, len);
	return 0;
}

static int salsa20_setkey(void *ctx, const uint8_t *key, size_t len, int mode)
{
	drew::Salsa20 *p = reinterpret_cast<drew::Salsa20 *>(ctx);
	p->SetKey(key, len);
	return 0;
}

static int salsa20_encrypt(void *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::Salsa20 *p = reinterpret_cast<drew::Salsa20 *>(ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int salsa20_fini(void **ctx, int flags)
{
	drew::Salsa20 *p = reinterpret_cast<drew::Salsa20 *>(*ctx);
	if (flags & DREW_STREAM_FINI_NO_DEALLOC)
		p->~Salsa20();
	else {
		delete p;
		*ctx = NULL;
	}
	return 0;
}

PLUGIN_FUNCTBL(salsa20, salsa20_info, salsa20_init, salsa20_setiv, salsa20_setkey, salsa20_encrypt, salsa20_encrypt, salsa20_test, salsa20_fini, salsa20_clone);
PLUGIN_DATA_START()
PLUGIN_DATA(salsa20, "Salsa20")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

}

drew::Salsa20::Salsa20()
{
}


void drew::Salsa20::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	m_nbytes = 0;
}

void drew::Salsa20::SetNonce(const uint8_t *iv, size_t sz)
{
	m_ks.SetNonce(iv, sz);
}

void drew::Salsa20::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	const uint8_t *buf = m_buf + (sizeof(m_buf) - m_nbytes);
	while (m_nbytes-- && len--)
		*out++ = *in++ ^ *buf++;
	while (len) {
		m_ks.GetValue(m_buf);
		m_nbytes = sizeof(m_buf);
		buf = m_buf;
		while (m_nbytes-- && len--)
			*out++ = *in++ ^ *buf++;
	}
	if (m_nbytes > sizeof(m_buf))
		m_nbytes = 0;
}

void drew::Salsa20::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::Salsa20Keystream::endian_t E;

drew::Salsa20Keystream::Salsa20Keystream()
{
	Reset();
	ctr = 0;
}

void drew::Salsa20Keystream::SetKey(const uint8_t *key, size_t sz)
{
	keysz = sz;
	E::Copy(state+1, key, 16);
	if (sz == 16)
		E::Copy(state+11, key, 16);
	else // sz == 32
		E::Copy(state+11, key+16, 16);
}

void drew::Salsa20Keystream::SetNonce(const uint8_t *iv, size_t sz)
{
	E::Copy(state+6, iv, sz);

	state[ 0] = 0x61707865;
	state[ 5] = (keysz == 16) ? 0x3120646e : 0x3320646e;
	state[10] = (keysz == 16) ? 0x79622d36 : 0x79622d32;
	state[15] = 0x6b206574;
}

inline void drew::Salsa20Keystream::DoQuarterRound(uint32_t &a, uint32_t &b,
		uint32_t &c, uint32_t &d)
{
	b ^= RotateLeft(a + d,  7);
	c ^= RotateLeft(b + a,  9);
	d ^= RotateLeft(c + b, 13);
	a ^= RotateLeft(d + c, 18);
}

#ifdef DREW_TEST
int drew::Salsa20Keystream::Test()
{
	int res = 0;
	res |= TestHash();
	res <<= 1;
	res |= TestDoubleRound();
	res <<= 1;
	res |= TestColumnRound();
	res <<= 1;
	res |= TestRowRound();
	res <<= 7;
	res |= TestQuarterRound();
	return res;
}

int drew::Salsa20Keystream::TestQuarterRound()
{
	static const uint32_t tests[7][8] = {
		{
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000
		},
		{
			0x00000001, 0x00000000, 0x00000000, 0x00000000,
			0x08008145, 0x00000080, 0x00010200, 0x20500000
		},
		{
			0x00000000, 0x00000001, 0x00000000, 0x00000000,
			0x88000100, 0x00000001, 0x00000200, 0x00402000
		},
		{
			0x00000000, 0x00000000, 0x00000001, 0x00000000,
			0x80040000, 0x00000000, 0x00000001, 0x00002000
		},
		{
			0x00000000, 0x00000000, 0x00000000, 0x00000001,
			0x00048044, 0x00000080, 0x00010000, 0x20100001
		},
		{
			0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137,
			0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3
		},
		{
			0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b,
			0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c
		}
	};

	int res = 0;
	for (size_t i = 0; i < 7; i++) {
		uint32_t buf[4];
		memcpy(buf, tests[i], sizeof(buf));
		DoQuarterRound(buf[0], buf[1], buf[2], buf[3]);
		res |= (!!memcmp(buf, tests[i]+4, sizeof(buf))) << i;
	}
	return res;
}

int drew::Salsa20Keystream::TestRowRound()
{
	static const uint32_t test[16] = {
		0x08008145, 0x00000080, 0x00010200, 0x20500000,
		0x20100001, 0x00048044, 0x00000080, 0x00010000,
		0x00000001, 0x00002000, 0x80040000, 0x00000000,
		0x00000001, 0x00000200, 0x00402000, 0x88000100
	};
	uint32_t buf[16];
	memset(buf, 0, sizeof(buf));
	buf[0] = buf[4] = buf[8] = buf[12] = 0x00000001;
	DoRowRound(buf);
	return !!memcmp(buf, test, sizeof(buf));
}

int drew::Salsa20Keystream::TestColumnRound()
{
	static const uint32_t test[16] = {
		0x10090288, 0x00000000, 0x00000000, 0x00000000,
		0x00000101, 0x00000000, 0x00000000, 0x00000000,
		0x00020401, 0x00000000, 0x00000000, 0x00000000,
		0x40a04001, 0x00000000, 0x00000000, 0x00000000
	};
	uint32_t buf[16];
	memset(buf, 0, sizeof(buf));
	buf[0] = buf[4] = buf[8] = buf[12] = 0x00000001;
	DoColumnRound(buf);
	return !!memcmp(buf, test, sizeof(buf));
}

int drew::Salsa20Keystream::TestDoubleRound()
{
	static const uint32_t test[16] = {
		0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
		0x08000090, 0x02402200, 0x00004000, 0x00800000,
		0x00010200, 0x20400000, 0x08008104, 0x00000000,
		0x20500000, 0xa0000040, 0x0008180a, 0x612a8020
	};
	uint32_t buf[16];
	memset(buf, 0, sizeof(buf));
	buf[0] = 0x00000001;
	DoDoubleRound(buf);
	return !!memcmp(buf, test, sizeof(buf));
}

int drew::Salsa20Keystream::TestHash()
{
	static const uint32_t in[16] = {
		0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
		0x100f0e0d, 0x3320646e, 0x68676665, 0x6c6b6a69,
		0x706f6e6d, 0x74737271, 0x79622d32, 0xcccbcac9,
		0xd0cfcecd, 0xd4d3d2d1, 0xd8d7d6d5, 0x6b206574
	};
	static const uint32_t out[16] = {
		0x27442545, 0xc16b0f29, 0x067a8bff, 0x62d9e9aa,
		0x6ab69059, 0x41c83315, 0x22de31ef, 0x7e2872d7,
		0xe107c568, 0x021f99c5, 0xb04c4e66, 0xb8f6f554,
		0x8285a0b1, 0x77954806, 0xec84c3c0, 0x4af667ea,
	};
	uint32_t buf[16];
	DoHash(buf, in);
	return !!memcmp(buf, out, sizeof(buf));
}
#endif

inline void drew::Salsa20Keystream::DoRowRound(uint32_t *x)
{
	DoQuarterRound(x[ 0], x[ 1], x[ 2], x[ 3]);
	DoQuarterRound(x[ 5], x[ 6], x[ 7], x[ 4]);
	DoQuarterRound(x[10], x[11], x[ 8], x[ 9]);
	DoQuarterRound(x[15], x[12], x[13], x[14]);
}


inline void drew::Salsa20Keystream::DoColumnRound(uint32_t *x)
{
	DoQuarterRound(x[ 0], x[ 4], x[ 8], x[12]);
	DoQuarterRound(x[ 5], x[ 9], x[13], x[ 1]);
	DoQuarterRound(x[10], x[14], x[ 2], x[ 6]);
	DoQuarterRound(x[15], x[ 3], x[ 7], x[11]);
}

inline void drew::Salsa20Keystream::DoDoubleRound(uint32_t *x)
{
	DoColumnRound(x);
	DoRowRound(x);
}

void drew::Salsa20Keystream::Reset()
{
	ctr = 0;
}

inline void drew::Salsa20Keystream::DoHash(uint32_t *cur, const uint32_t *st)
{
	memcpy(cur, st, 16 * sizeof(uint32_t));

	for (size_t i = 0; i < 10; i++)
		DoDoubleRound(cur);
	for (size_t i = 0; i < 16; i++)
		cur[i] += st[i];
}

void drew::Salsa20Keystream::GetValue(uint8_t buf[64])
{
	uint32_t cur[16];

	state[8] = uint32_t(ctr);
	state[9] = ctr >> 32;
	DoHash(cur, state);
	ctr++;
	E::Copy(buf, cur, sizeof(cur));
}
