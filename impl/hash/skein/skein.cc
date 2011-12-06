/*-
 * Copyright © 2011 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "internal.h"
#include "threefish/threefish.hh"
#include "skein.hh"
#include "testcase.hh"
#include "util.hh"
#include "hash-plugin.hh"

extern "C" {

static const int skeinhash_sizes[] = {
	28, 32, 48, 64
};

PLUGIN_STRUCTURE_VARIABLE(skein, Skein)
PLUGIN_DATA_START()
PLUGIN_DATA(skein, "Skein")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(skein)

static int skeintest(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;

	typedef VariableSizedHashTestCase<Skein, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<Skein, 256/8> TestCase256;
	typedef VariableSizedHashTestCase<Skein, 384/8> TestCase384;
	typedef VariableSizedHashTestCase<Skein, 512/8> TestCase512;

	res |= !TestCase512("", 0).Test("bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a");

	return res;
}
}

typedef drew::Skein::endian_t E;

drew::Skein::Skein(size_t len) : m_digest_size(len)
{
	Reset();
}

#define BIT_FIRST (uint64_t(1) << 62)
#define BIT_FINAL (uint64_t(1) << 63)
#define TYPE_CFG (uint64_t( 4) << 56)
#define TYPE_MSG (uint64_t(48) << 56)
#define TYPE_OUT (uint64_t(63) << 56)

void drew::Skein::Reset()
{
	uint8_t config[32] = {
		// S     H     A     3, version 1,  reserved
		0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0x00, 0x00,
		// 512 bit output length
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// No tree values, reserved
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Reserved
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	E::Convert<uint16_t>(config+8, m_digest_size * 8);

	memset(m_hash, 0, sizeof(m_hash));

	memset(m_tweak, 0, sizeof(m_tweak));
	memset(m_len, 0, sizeof(m_len));
	m_tweak[1] |= TYPE_CFG | BIT_FIRST;
	UBI(m_hash, config, sizeof(config), m_tweak);

	memset(m_tweak, 0, sizeof(m_tweak));
	m_tweak[1] |= TYPE_MSG | BIT_FIRST;
	full = false;
	Initialize();
}

void drew::Skein::UBI(uint64_t *state, const uint8_t *m, size_t len,
		const uint64_t *tweak)
{
	uint64_t t[2];
	const uint64_t overflow = len & (block_size-1);

	memcpy(t, tweak, sizeof(t));
	t[1] &= ~BIT_FINAL;
	t[1] |= BIT_FIRST;

	for (size_t i = 0; i < (len / block_size); i++, m += block_size) {
		t[0] += block_size;
		if (!(len & block_size) && (i == ((len / block_size) - 1)))
			t[1] |= BIT_FINAL;

		UBIBlock(state, m, t);

		t[1] &= ~BIT_FIRST;
	}

	if (overflow) {
		t[0] += overflow;
		t[1] |= BIT_FINAL;
		uint8_t buf[block_size] = {0};
		memcpy(buf, m, len & (block_size-1));
		UBIBlock(state, buf, t);
	}
}

void drew::Skein::UBIBlock(uint64_t *state, const uint8_t *m,
		const uint64_t *tweak)
{
	uint64_t buf[block_size];
	const uint64_t *p;

	p = E::CopyIfNeeded(buf, m, sizeof(buf));

	UBIBlock(state, p, tweak);
}

void drew::Skein::UBIBlock(uint64_t *state, const uint64_t *m,
		const uint64_t *tweak)
{
	Threefish tf(tweak);
	tf.SetKey(state);
	tf.Encrypt(state, m);
	XorBuffers(state, m, block_size);
}

void drew::Skein::Update(const uint8_t *data, size_t len)
{
	const uint64_t t = m_len[0];
	const uint64_t off = t % block_size;
	uint8_t *buf = m_buf;

	if (!len)
		return;

	if (full)
		Transform(m_buf);
	full = false;

	if (off + len == block_size) {
		memcpy(buf+off, data, len);

		if (unlikely((m_len[0] += len) < t))
			m_len[1]++;
		full = true;
		return;
	}
	if (off + len < block_size) {
		memcpy(buf+off, data, len);

		if (unlikely((m_len[0] += len) < t))
			m_len[1]++;
		return;
	}
	if (off) {
		// off + len > block_size
		const size_t i = block_size-off;
		memcpy(buf+off, data, i);

		if (unlikely((m_len[0] += i) < t))
			m_len[1]++;

		Transform(buf);
		len -= i;
		data += i;
	}

	while (len > block_size) {
		if (unlikely((m_len[0] += block_size) < t))
			m_len[1]++;

		Transform(data);
		len -= block_size;
		data += block_size;
	}
	memcpy(buf, data, len);
	if (len == block_size)
		full = true;
	if (unlikely((m_len[0] += len) < t))
		m_len[1]++;
}

void drew::Skein::Pad()
{
	if (!full) {
		const uint64_t off = m_len[0] % block_size;
		memset(m_buf+off, 0, block_size-off);
	}
	Transform(m_buf, true);
}

void drew::Skein::Transform(const uint8_t *data, bool final)
{
	m_tweak[0] = m_len[0];
	m_tweak[1] |= final ? BIT_FINAL : 0;

	UBIBlock(m_hash, data, m_tweak);

	m_tweak[1] &= ~BIT_FIRST;
}

void drew::Skein::GetDigest(uint8_t *digest, size_t len, bool nopad)
{
	const uint8_t msg[8] = {0};
	const uint64_t tweak[2] = {0, TYPE_OUT | BIT_FIRST | BIT_FINAL};

	if (!nopad)
		Pad();

	UBI(m_hash, msg, sizeof(msg), tweak);
	E::Copy(digest, m_hash, len);
}
