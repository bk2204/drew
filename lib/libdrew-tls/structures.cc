/*-
 * Copyright © 2010–2011 brian m. carlson
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
#include "structures.hh"
#include "util.hh"

SerializedBuffer::SerializedBuffer()
{
	buf = 0;
	Reset();
}

SerializedBuffer::SerializedBuffer(size_t sz)
{
	buf = 0;
	Reset(sz);
}

SerializedBuffer::~SerializedBuffer()
{
	memset(buf, 0, buflen);
	free(buf);
	buf = 0;
}

SerializedBuffer::SerializedBuffer(const SerializedBuffer &b)
{
	off = b.off;
	len = b.len;
	buflen = b.buflen;
	posix_memalign((void **)&buf, 16, buflen);
	memcpy(buf, b.buf, buflen);
}

SerializedBuffer &SerializedBuffer::operator=(const SerializedBuffer &b)
{
	free(buf);

	off = b.off;
	len = b.len;
	buflen = b.buflen;
	posix_memalign((void **)&buf, 16, buflen);
	memcpy(buf, b.buf, buflen);
	return *this;
}

void SerializedBuffer::ResetPosition()
{
	off = 0;
}

void SerializedBuffer::Reset()
{
	Reset(512);
}

void SerializedBuffer::Reset(size_t sz)
{
	size_t space = (sz + 0x1ff) & ~0x1ff;
	posix_memalign((void **)&buf, 16, space);
	off = 0;
	len = 0;
	buflen = space;
	memset(buf, 0, buflen);
}

void SerializedBuffer::Put(uint8_t x)
{
	Put(&x, 1);
}

void SerializedBuffer::Put(const uint8_t *data, size_t datalen)
{
	ExtendIfNecessary(datalen);
	memcpy(buf+off, data, datalen);
	off += datalen;
	len += datalen;
}

void SerializedBuffer::Put(SerializedBuffer &sbuf)
{
	Put(sbuf.buf, sbuf.len);
}

void SerializedBuffer::Get(uint8_t &x)
{
	Get(&x, 1);
}

void SerializedBuffer::Get(uint8_t *data, size_t datalen)
{
	memcpy(data, buf+off, datalen);
	off += datalen;
}

void SerializedBuffer::Get(SerializedBuffer &sbuf, size_t datalen)
{
	uint8_t *data = new uint8_t[datalen];

	memcpy(data, buf+off, datalen);
	off += datalen;
	sbuf.Put(data, datalen);
	memset(data, 0, datalen);
	delete[] data;
}

void SerializedBuffer::Reserve(size_t space)
{
	if (space > buflen) {
		size_t extra = (space - buflen + 0x1ff) & ~0x1ff;
		uint8_t *tmp;
		posix_memalign((void **)&tmp, 16, buflen + extra);
		memset(tmp, 0, buflen + extra);
		memcpy(tmp, buf, buflen);
		memset(buf, 0, buflen);
		free(buf);
		buf = tmp;
		buflen += extra;
	}
}

void SerializedBuffer::ExtendIfNecessary(size_t space)
{
	Reserve(off + space);
}

size_t SerializedBuffer::GetLength() const
{
	return len;
}

ssize_t SerializedBuffer::BytesRemaining() const
{
	return ssize_t(len) - ssize_t(off);
}

const uint8_t *SerializedBuffer::GetPointer() const
{
	return buf + off;
}

const uint8_t *SerializedBuffer::GetPointer(size_t offset) const
{
	return buf + offset;
}

uint8_t *SerializedBuffer::GetPointer()
{
	return buf + off;
}

uint8_t *SerializedBuffer::GetPointer(size_t offset)
{
	return buf + offset;
}

size_t SerializedBuffer::GetOffset() const
{
	return off;
}

void SerializedBuffer::SetOffset(size_t offset)
{
	Reserve(offset);
	off = offset;
}
