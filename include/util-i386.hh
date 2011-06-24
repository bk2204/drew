#ifndef UTIL_I386_HH
#define UTIL_I386_HH

/* This file simply contains specializations for i386 and amd64 machines.  No
 * extra functionality is available here, only performance optimizations.  For
 * cleanliness reasons only, this file is split out of the main util.hh.
 */

#if !(defined(__i386__) || defined(__x86_64__))
#error "util-i386.hh is only for i386 and amd64 machines!"
#endif

#if defined(__GNUC__)
/* GCC does a crappy job in optimizing non-constant rotates (see PR45216).  As a
 * consequence, we have to help it out.  Do note, though, that unconditionally
 * using the instructions hurts performance when n is a constant.
 */
#if defined(__i386__) || defined(__x86_64__)
#define ROTATE(bits, direction, suffix, asmdirection, sh, osh) \
template<> \
inline uint ## bits ## _t Rotate ## direction(uint ## bits ##_t x, size_t n) \
{ \
	if (__builtin_constant_p(n)) \
		return (x sh n) | (x osh (bits - n)); \
	__asm__("ro" #asmdirection #suffix " %%cl, %0" \
			: "=r"(x) \
			: "0"(x), "c"(n)); \
	return x; \
}

ROTATE(16, Left, w, l, <<, >>)
ROTATE(32, Left, l, l, <<, >>)
ROTATE(16, Right, w, r, >>, <<)
ROTATE(32, Right, l, r, >>, <<)
#if defined(__x86_64__)
ROTATE(64, Left, q, l, <<, >>)
ROTATE(64, Right, q, r, >>, <<)
#endif
#endif
#undef ROTATE
#endif

#endif
