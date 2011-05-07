#ifndef INTERNAL_H
#define INTERNAL_H

#define DREW_TLS_IN_BUILD 1

#define RETFAIL(x) do { if ((res = (x))) return res; } while (0)
#define URETFAIL(m, x) do { \
	if ((res = (x))) { UNLOCK(m); return res; } \
} while (0)

#ifdef DREW_TLS_THREAD_SAFE
#define LOCK(x)		pthread_mutex_lock(&((x)->mutex));
#define UNLOCK(x)	pthread_mutex_unlock(&((x)->mutex));
#else
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

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#endif
