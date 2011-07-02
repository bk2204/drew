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

template<>
inline uint8_t EndianBase::GetArrayByte(const uint64_t *arr, size_t n)
{
	const uint8_t *p = reinterpret_cast<const uint8_t *>(arr);
	return p[n];
}

#if defined(__GNUC__) && defined(__SSSE3__) && defined(VECTOR_T)
template<>
template<>
inline uint8_t *Endian<DREW_BIG_ENDIAN>::Copy<uint32_t>(uint8_t *dest, const uint32_t *src, size_t len)
{
	typedef char vector_t __attribute__ ((vector_size (16)));
	const vector_t perm = {0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c};
	if (!(len % 16)) {
		for (size_t i = 0; i < len; i += 16) {
			vector_t buf;
			memcpy(&buf, src+(i/4), 16);
			buf = __builtin_ia32_pshufb128(buf, perm);
			memcpy(dest+i, &buf, 16);
		}
		return dest;
	}
	else
		return CopyByConvert(dest, src, len);
}
template<>
template<>
inline uint32_t *Endian<DREW_BIG_ENDIAN>::Copy<uint32_t>(uint32_t *dest, const uint8_t *src, size_t len)
{
	typedef char vector_t __attribute__ ((vector_size (16)));
	const vector_t perm = {0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c};
	if (!(len % 16)) {
		for (size_t i = 0; i < len; i += 16) {
			vector_t buf;
			memcpy(&buf, src+i, 16);
			buf = __builtin_ia32_pshufb128(buf, perm);
			memcpy(dest+(i/4), &buf, 16);
		}
		return dest;
	}
	else
		return CopyByConvert(dest, src, len);
}
#endif

#endif
