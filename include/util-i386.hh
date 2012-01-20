/*-
 * Copyright © 2011 brian m. carlson
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
#ifndef UTIL_I386_HH
#define UTIL_I386_HH

/* This file simply contains specializations for i386 and amd64 machines.  Most
 * of this file provides no extra functionality, only performance optimizations.
 * The sole exception is the GetCpuid function, which is used to determine if
 * certain cryptographic operations are available on the processor.
 */

#if !(defined(__i386__) || defined(__x86_64__))
#error "util-i386.hh is only for i386 and amd64 machines!"
#endif

HIDE()
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

inline int GetCpuid(uint32_t func, uint32_t &a, uint32_t &b, uint32_t &c,
		uint32_t &d)
{
#if defined(DREW_COMPILER_GCCLIKE)
#if defined(__amd64__)
	__asm__ __volatile__("cpuid"
			: "=a"(a), "=b"(b), "=c"(c), "=d"(d)
			: "a"(func));
#else
	// GCC refuses to compile the code if we use the =b constraint because ebx
	// is the PIC register.  Apparently it never occurred to it that it could
	// surround the cpuid instruction with push/movl/pop.  We do it ourselves so
	// that it will compile.
	__asm__ __volatile__("push %%ebx\n\tcpuid\n\tmovl %%ebx, %1\n\tpop %%ebx\n"
			: "=a"(a), "=r"(b), "=c"(c), "=d"(d)
			: "a"(func));
#endif
	return 0;
#else
	return -DREW_ERR_NOT_IMPL;
#endif
}

template<>
inline uint8_t EndianBase::GetArrayByte(const uint64_t *arr, size_t n)
{
	const uint8_t *p = reinterpret_cast<const uint8_t *>(arr);
	return p[n];
}

#if defined(DREW_COMPILER_GCCLIKE) && defined(__SSSE3__) && defined(VECTOR_T)
typedef long long int drew__vector64_t __attribute__((vector_size(16)));

template<>
template<>
inline uint8_t *Endian<DREW_BIG_ENDIAN>::Copy<drew__vector64_t>(uint8_t *dest, const drew__vector64_t *src, size_t len)
{
	typedef char vector_t __attribute__ ((vector_size (16)));
	const vector_t perm = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	for (size_t i = 0, j = 0; i < len; i += 16, j++) {
		vector_t buf = vector_t(src[j]);
		buf = __builtin_ia32_pshufb128(buf, perm);
		memcpy(dest+i, &buf, sizeof(buf));
	}
	return dest;
}
template<>
template<>
inline drew__vector64_t *Endian<DREW_BIG_ENDIAN>::Copy<drew__vector64_t>(drew__vector64_t *dest, const uint8_t *src, size_t len)
{
	typedef char vector_t __attribute__ ((vector_size (16)));
	const vector_t perm = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	for (size_t i = 0, j = 0; i < len; i += 16, j++) {
		vector_t buf;
		memcpy(&buf, src+i, sizeof(buf));
		buf = __builtin_ia32_pshufb128(buf, perm);
		dest[j] = drew__vector64_t(buf);
	}
	return dest;
}

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
UNHIDE()

#endif
