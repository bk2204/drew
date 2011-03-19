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

#endif
