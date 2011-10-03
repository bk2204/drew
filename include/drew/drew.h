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
#ifndef DREW_DREW_H
#define DREW_DREW_H

/* Not that this will work in Win32 without a decent amount of work, but hey...
 *
 * Code pulled from the GCC wiki.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#ifdef DREW_IN_BUILD

#ifdef __GNUC__
#define DREW_SYM_PUBLIC __attribute__ ((dllexport))
#else
#define DREW_SYM_PUBLIC __declspec(dllexport)
#endif

#else

#ifdef __GNUC__
#define DREW_SYM_PUBLIC __attribute__ ((dllimport))
#else
#define DREW_SYM_PUBLIC __declspec(dllimport)
#endif

#endif

#define DREW_SYM_HIDDEN

#else

#if defined(__GNUC__) && __GNUC__ >= 4
#define DREW_SYM_PUBLIC __attribute__ ((visibility("default")))
#define DREW_SYM_HIDDEN __attribute__ ((visibility("hidden")))
#else
#define DREW_SYM_PUBLIC
#define DREW_SYM_HIDDEN
#endif

#endif

#include <drew/plugin.h>

#endif
