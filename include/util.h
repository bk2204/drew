#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* There are a couple different types of functionality we need from the system.
 * One of them is a definition of BYTE_ORDER, LITTLE_ENDIAN, and BIG_ENDIAN.
 * Another is a consistent big-endian or little-endian presentation of bytes on
 * the hardware.  Any system providing these is sufficient for our purposes.  We
 * also rely on htonl and htons being in one of the above two headers, which is
 * reasonable on all POSIX systems.
 *
 * If the system provides additional functionality, terrific.  We define macros
 * for these and use them when possible.  They are:
 *
 * FEATURE_ENDIAN3: We have the functionality described in glibc's endian(3),
 * specifically hto[bl]e{16,32,64} and [bl]e{16,32,64}toh.
 *
 * FEATURE_ENDIAN3_OPENBSD: We have FEATURE_ENDIAN3 functionality, but it's
 * written as hto[bl]e{16,32,64} and [bl]etoh{16,32,64}.
 *
 * FEATURE_BYTESWAP_GNU: We have bswap_{16,32,64}.
 *
 * FEATURE_BYTESWAP_BSD: We have bswap{16,32,64}.
 *
 * FEATURE_BYTESWAP_OPENBSD: We have swap{16,32,64}.
 *
 * FEATURE_BYTESWAP: We have one of FEATURE_BYTESWAP_{GNU,BSD,OPENBSD}.
 */
#if defined(__GLIBC__)
#include <endian.h>
#include <byteswap.h>
#define FEATURE_ENDIAN3
#define FEATURE_BYTESWAP_GNU
#define FEATURE_BYTESWAP
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#undef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#include <sys/endian.h>
#define FEATURE_ENDIAN3
#define FEATURE_BYTESWAP_BSD
#define FEATURE_BYTESWAP
#elif defined(__NetBSD__)
#include <sys/endian.h>
#include <sys/bswap.h>
#define FEATURE_ENDIAN3
#define FEATURE_BYTESWAP_BSD
#define FEATURE_BYTESWAP
#elif defined(__OpenBSD__) || defined(__MirBSD__)
/* MirBSD defines __OpenBSD__, too!? */
#undef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#include <sys/endian.h>
#define FEATURE_ENDIAN3_OPENBSD
#define FEATURE_BYTESWAP_OPENBSD
#define FEATURE_BYTESWAP
#endif

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
#error "BYTE_ORDER macros must be defined!"
#endif

#if defined(__i386__) || defined(__amd64__)
#define NEEDS_ALIGNMENT 0
#elif defined(__sparc) || defined(sparc)
#define NEEDS_ALIGNMENT 1
#else
#define NEEDS_ALIGNMENT 1
#endif

#define FAST_ALIGNMENT 16
#if defined(__GNUC__)
#define ALIGNED_T __attribute__((aligned(FAST_ALIGNMENT)))
#else
#define ALIGNED_T
#endif

#if defined(__GNUC__)
/* Enable the use of vector types.  If the processor supports vectorization, GCC
 * will generate vectorized code.  If they are not, GCC will automatically
 * generate equivalent non-vector code.
 */
#define VECTOR_T
#define BRANCH_PREDICTION
#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ == 16
#define FEATURE_128_BIT_INTEGERS
typedef __int128_t int128_t;
typedef __uint128_t uint128_t; 
#endif
#endif

#ifdef __GNUC__
#define HIDE() _Pragma("GCC visibility push(hidden)")
#define UNHIDE() _Pragma("GCC visibility pop")
#define EXPORT() _Pragma("GCC visibility push(default)")
#define UNEXPORT() _Pragma("GCC visibility pop")
#else
#define HIDE()
#define UNHIDE()
#define EXPORT()
#define UNEXPORT()
#endif

#if !defined(__STDC_ISO_10646__)
#if WCHAR_MAX < 0x10ffff
#if WCHAR_MIN == 0
#define wchar_t uint32_t
#else
#define wchar_t int32_t
#endif
#endif
#endif

#define STATIC_ASSERT(e) ((void)sizeof(char[1 - 2*!(e)]))

HIDE()
inline void xor_aligned(uint8_t *outp, const uint8_t *inp, const uint8_t *xorp, size_t len)
{
	struct aligned_data {
		uint8_t data[16] ALIGNED_T;
	};

	len /= 16;

	struct aligned_data *out = (struct aligned_data *)outp;
	const struct aligned_data *in = (struct aligned_data *)inp;
	const struct aligned_data *x = (struct aligned_data *)xorp;
	for (size_t i = 0; i < len; i++, out++, in++, x++) {
#ifdef VECTOR_T
		typedef int vector_t __attribute__ ((vector_size (16)));
		vector_t buf, xbuf;
		memcpy(&buf, in->data, 16);
		memcpy(&xbuf, x->data, 16);
		buf ^= xbuf;
		memcpy(out->data, &buf, 16);
#else
		for (size_t j = 0; j < 16; j++) {
			out->data[j] = in->data[j] ^ x->data[j];
		}
#endif
	}
}

inline void xor_aligned2(uint8_t *outp, const uint8_t *xorp, size_t len)
{
	struct aligned_data {
		uint8_t data[16] ALIGNED_T;
	};

	len /= 16;

	struct aligned_data *out = (struct aligned_data *)outp;
	const struct aligned_data *x = (struct aligned_data *)xorp;
	for (size_t i = 0; i < len; i++, out++, x++) {
#ifdef VECTOR_T
		typedef int vector_t __attribute__ ((vector_size (16)));
		vector_t buf, xbuf;
		memcpy(&buf, out->data, 16);
		memcpy(&xbuf, x->data, 16);
		buf ^= xbuf;
		memcpy(out->data, &buf, 16);
#else
		for (size_t j = 0; j < 16; j++) {
			out->data[j] ^= x->data[j];
		}
#endif
	}
}

inline void xor_buffers(uint8_t *outp, const uint8_t *inp, const uint8_t *xorp,
		size_t len)
{
	for (size_t i = 0; i < len; i++)
		*outp++ = *inp++ ^ *xorp++;
}

inline void xor_buffers2(uint8_t *outp, const uint8_t *xorp, size_t len)
{
	for (size_t i = 0; i < len; i++)
		*outp++ ^= *xorp++;
}
UNHIDE()

#ifdef BRANCH_PREDICTION
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#endif
