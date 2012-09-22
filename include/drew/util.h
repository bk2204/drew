#ifndef DREW_UTIL_H
#define DREW_UTIL_H

#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#define DREW_COMPILER_GCCLIKE
/* eglibc defines this to nothing if the compiler isn't GCC, even though clang
 * supports attributes.
 */
#ifdef __linux__
#include <features.h>
#undef __attribute__
#endif
#endif

/* Not that this will work in Win32 without a decent amount of work, but hey...
 *
 * Code pulled from the GCC wiki.
 */
#ifdef __cplusplus
#define DREW_SYM_C_ABI extern "C"
#else
#define DREW_SYM_C_ABI
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#ifdef DREW_IN_BUILD

#ifdef DREW_COMPILER_GCCLIKE
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((dllexport))
#else
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __declspec(dllexport)
#endif

#else

#ifdef DREW_COMPILER_GCCLIKE
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((dllimport))
#else
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __declspec(dllimport)
#endif

#endif

#define DREW_SYM_HIDDEN

#else

#ifdef DREW_COMPILER_GCCLIKE
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((visibility("default")))
#define DREW_SYM_HIDDEN DREW_SYM_C_ABI __attribute__ ((visibility("hidden")))
#else
#define DREW_SYM_PUBLIC
#define DREW_SYM_HIDDEN
#endif

#endif

#endif
