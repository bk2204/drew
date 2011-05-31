#ifndef UTIL_H
#define UTIL_H

#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
#endif

#define STATIC_ASSERT(e) ((void)sizeof(char[1 - 2*!(e)]))

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

#endif
