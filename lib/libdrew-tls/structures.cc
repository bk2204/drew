#include "structures.hh"
#include "util.hh"

SerializedBuffer::SerializedBuffer()
{
	Reset();
}

SerializedBuffer::SerializedBuffer(size_t sz)
{
	Reset(sz);
}

SerializedBuffer::~SerializedBuffer()
{
	memset(buf, 0, buflen);
	free(buf);
}

SerializedBuffer::SerializedBuffer(const SerializedBuffer &b)
{
	memset(buf, 0, buflen);
	free(buf);

	off = b.off;
	len = b.len;
	buflen = b.buflen;
	posix_memalign((void **)&buf, 16, buflen);
	memcpy(buf, b.buf, buflen);
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
		memcpy(tmp, buf, buflen);
		memset(buf, 0, buflen);
		free(buf);
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
