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
#ifndef DREW_TLS_STRUCTURES_HH
#define DREW_TLS_STRUCTURES_HH

#include "internal.h"
#include "util.hh"

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include <drew-tls/drew-tls.h>

// None of these classes are thread-safe.

class MutexLock
{
	public:
		MutexLock(pthread_mutex_t *m)
		{
			mutex = m;
			pthread_mutex_lock(mutex);
		}
		~MutexLock()
		{
			pthread_mutex_unlock(mutex);
		}
	private:
		pthread_mutex_t *mutex;
};

class SerializedBuffer
{
	public:
		SerializedBuffer();
		SerializedBuffer(size_t sz);
		SerializedBuffer(const SerializedBuffer &b);
		~SerializedBuffer();
		void ResetPosition();
		void Reset();
		void Put(uint8_t x);
		void Put(const uint8_t *data, size_t datalen);
		void Put(SerializedBuffer &sbuf);
		template<class T>
		void Put(T x)
		{
			uint8_t buf[sizeof(T)];
			BigEndian::Copy(buf, &x, sizeof(T));
			Put(buf, sizeof(T));
		}
		void Get(uint8_t &x);
		template<class T>
		void Get(T &x)
		{
			uint8_t buf[sizeof(T)];
			Get(buf, sizeof(T));
			BigEndian::Copy(&x, buf, sizeof(T));
		}
		void Get(uint8_t *data, size_t datalen);
		void Get(SerializedBuffer &sbuf, size_t datalen);
		size_t GetLength() const;
		size_t GetOffset() const;
		ssize_t BytesRemaining() const;
		const uint8_t *GetPointer() const;
		const uint8_t *GetPointer(size_t offset) const;
		uint8_t *GetPointer();
		uint8_t *GetPointer(size_t offset);
		void Reserve(size_t);
	protected:
		void Reset(size_t);
		void ExtendIfNecessary(size_t space);
	private:
		uint8_t *buf;
		size_t len;		// The length of the actual data.
		size_t off;
		size_t buflen;	// The length of buf.
};

struct ProtocolVersion
{
	uint8_t major;
	uint8_t minor;
	int Compare(const ProtocolVersion &x)
	{
		if (this->major < x.major)
			return -1;
		if (this->major > x.major)
			return 1;
		if (this->minor < x.minor)
			return -1;
		if (this->minor > x.minor)
			return 1;
		return 0;
	}
	int ReadFromBuffer(SerializedBuffer &buf)
	{
		if (buf.BytesRemaining() < 2)
			return -DREW_TLS_ERR_RECORD_OVERFLOW;
		buf.Get(major);
		buf.Get(minor);
		return 0;
	}
	void WriteToBuffer(SerializedBuffer &buf)
	{
		buf.Put(major);
		buf.Put(minor);
	}
};

struct Record
{
	uint8_t type; // ContentType
	ProtocolVersion version;
	uint16_t length;
	SerializedBuffer data;

	int ReadFromBuffer(SerializedBuffer &buf)
	{
		if (buf.BytesRemaining() < 5)
			return -DREW_TLS_ERR_RECORD_OVERFLOW;
		buf.Get(type);
		version.ReadFromBuffer(buf);
		buf.Get(length);
		if (buf.BytesRemaining() < length)
			return -DREW_TLS_ERR_RECORD_OVERFLOW;
		buf.Get(data, length);
		return 0;
	}
	void WriteToBuffer(SerializedBuffer &buf)
	{
		buf.Put(type);
		version.WriteToBuffer(buf);
		buf.Put(length);
		buf.Put(data);
	}
};

struct AlertMessage
{
	uint8_t level;
	uint8_t description;
	AlertMessage() {}
	AlertMessage(const Record &rec)
	{
		SerializedBuffer b = rec.data;
		b.ResetPosition();
		b.Get(level);
		b.Get(description);
	}
};

struct HandshakeMessage
{
	uint8_t type;
	uint32_t length;
	SerializedBuffer data;
};

#endif
