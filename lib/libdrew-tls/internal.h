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
#ifndef INTERNAL_H
#define INTERNAL_H

#define DREW_TLS_IN_BUILD 1

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

#define RETFAIL(x) do { \
	int result_code; \
	if ((result_code = (x))) return result_code; } while (0)
#define URETFAIL(m, x) do { \
	int result_code; \
	if ((result_code = (x))) { UNLOCK(m); return result_code; } \
} while (0)

#ifdef DREW_TLS_THREAD_SAFE
#include <pthread.h>
#define DREW_TLS_MUTEX_DECL() pthread_mutex_t mutex;
#define DREW_TLS_MUTEX_INIT(x) pthread_mutex_init(&((x)->mutex), NULL);
#define DREW_TLS_MUTEX_FINI(x) pthread_mutex_destroy(&((x)->mutex));
#ifdef __cplusplus
#define LOCK(x)		MutexLock(&((x)->mutex));
#define UNLOCK(x)
#else
#define LOCK(x)		pthread_mutex_lock(&((x)->mutex));
#define UNLOCK(x)	pthread_mutex_unlock(&((x)->mutex));
#endif
#else
#define DREW_TLS_MUTEX_DECL()
#define DREW_TLS_MUTEX_INIT(x)
#define DREW_TLS_MUTEX_FINI(x)
#define LOCK(x)
#define UNLOCK(x)
#endif

#define STATIC_ASSERT(e) ((void)sizeof(char[1 - 2*!(e)]))

// Buffer writes.
#define BWR_INTERNAL(buf, val, sz) do { \
	memcpy(buf, &val, sz); \
	buf += sz; \
} while (0)
// Some fixed-size object.
#define BWR_OBJ(buf, val) BWR_INTERNAL(buf, val, sizeof(val))
// A buffer of some sort.
#define BWR_BUF(buf, val, sz) do { \
	memcpy(buf, val, sz); \
	buf += sz; \
} while (0)
// A fixed-size array.
#define BWR_ARR(buf, val) BWR_BUF(buf, val, sizeof(val));
// Counted buffers.
#define BWR_BUF8(buf, val, sz) do { \
	BWR8(buf, sz); \
	BWR_BUF(buf, val, sz); \
} while (0)
#define BWR_BUF16(buf, val, sz) do { \
	BWR16(buf, sz); \
	BWR_BUF(buf, val, sz); \
} while (0)
// Various fixed-size types, converted to big-endian.
#define BWR8(buf, val)  do { \
	STATIC_ASSERT(sizeof(val) == 1); \
	BWR_INTERNAL(buf, val, 1); \
} while (0)
#define BWR16(buf, val) do { \
	uint16_t bwrtmp; \
	STATIC_ASSERT(sizeof(val) == 2); \
	bwrtmp = htons(val); \
	BWR_INTERNAL(buf, bwrtmp, 2); \
} while (0)
#define BWR32(buf, val) do { \
	uint32_t bwrtmp; \
	STATIC_ASSERT(sizeof(val) == 4); \
	bwrtmp = htonl(val); \
	BWR_INTERNAL(buf, bwrtmp, 4); \
} while (0)

// Buffer reads.
#define BRD_INTERNAL(buf, val, sz) do { \
	memcpy(&val, buf, sz); \
	buf += sz; \
} while (0)
// Some fixed-size object.
#define BRD_OBJ(buf, val) BWR_INTERNAL(buf, val, sizeof(val))
// A buffer of some sort.
#define BRD_BUF(buf, val, sz) do { \
	memcpy(val, buf, sz); \
	buf += sz; \
} while (0)
// A fixed-size array.
#define BRD_ARR(buf, val) BRD_BUF(buf, val, sizeof(val));
// Counted buffers.
#define BRD_BUF8(buf, val, sz) do { \
	BRD8(buf, sz); \
	BRD_BUF(buf, val, sz); \
} while (0)
#define BRD_BUF16(buf, val, sz) do { \
	BRD16(buf, sz); \
	BRD_BUF(buf, val, sz); \
} while (0)
// Various fixed-size types, converted to big-endian.
#define BRD8(buf, val)  do { \
	STATIC_ASSERT(sizeof(val) == 1); \
	BRD_INTERNAL(buf, val, 1); \
} while (0)
#define BRD16(buf, val) do { \
	uint16_t bwrtmp; \
	STATIC_ASSERT(sizeof(val) == 2); \
	BRD_INTERNAL(buf, bwrtmp, 2); \
	val = htons(bwrtmp); \
} while (0)
#define BRD32(buf, val) do { \
	uint32_t bwrtmp; \
	STATIC_ASSERT(sizeof(val) == 4); \
	BRD_INTERNAL(buf, bwrtmp, 4); \
	val = htonl(bwrtmp); \
} while (0)

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#endif
