#ifndef DREW_UTIL_H
#define DREW_UTIL_H

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

#ifdef __GNUC__
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((dllexport))
#else
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __declspec(dllexport)
#endif

#else

#ifdef __GNUC__
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((dllimport))
#else
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __declspec(dllimport)
#endif

#endif

#define DREW_SYM_HIDDEN

#else

#if defined(__GNUC__) && __GNUC__ >= 4
#define DREW_SYM_PUBLIC DREW_SYM_C_ABI __attribute__ ((visibility("default")))
#define DREW_SYM_HIDDEN DREW_SYM_C_ABI __attribute__ ((visibility("hidden")))
#else
#define DREW_SYM_PUBLIC
#define DREW_SYM_HIDDEN
#endif

#endif

#endif
