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
#ifndef DREW_MEM_H
#define DREW_MEM_H

#include <stddef.h>

#include <drew/drew.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The op parameter to drew_mem_adjust. */
#define DREW_MEM_SECMEM		1
#define DREW_MEM_ALLOC		2
#define DREW_MEM_POOL		3

/* Flags for drew_mem_adjust with DREW_MEM_SECMEM.
 *
 * FAIL_OK allows the secure memory allocator to succeed even if memory locking
 * fails.
 * NO_LOCK prevents the secure memory allocator from attempting to lock memory
 * in the first place.
 */
#define DREW_MEM_SECMEM_FAIL_OK		(1 << 0)
#define DREW_MEM_SECMEM_NO_LOCK		(1 << 1)

/* Flags for drew_mem_adjust with DREW_MEM_ALLOC.
 *
 * PREBLOCK allocates 16 bytes more than requested and uses this pre-block area
 * to keep track of the size and other data.  This avoids the overhead of
 * maintaining a linked list of allocated chunks while still permitting that
 * memory to be zeroed.  However, it means that memory allocated from the
 * drew_mem functions cannot be used directly with the system allocation
 * functions.
 */
#define DREW_MEM_ALLOC_PREBLOCK		(1 << 10)

/* Flags for drew_mem_adjust with DREW_MEM_POOL.
 *
 * FREEABLE allows a particular pool to be freed all at once.  This necessitates
 * keeping a linked list, and ALLOC_PREBLOCK is not useful (except for wasting
 * memory).  This also requires that freeing memory allocated by this pool must
 * be done with the drew_mem functions and not by free; otherwise, double
 * freeing may occur.
 */
#define DREW_MEM_POOL_FREEABLE		(1 << 20)

DREW_SYM_PUBLIC
void *drew_mem_malloc(size_t size);
DREW_SYM_PUBLIC
void *drew_mem_calloc(size_t nmemb, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_realloc(void *ptr, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_memdup(const void *ptr, size_t size);
DREW_SYM_PUBLIC
void drew_mem_free(void *ptr);

DREW_SYM_PUBLIC
void *drew_mem_smalloc(size_t size);
DREW_SYM_PUBLIC
void *drew_mem_scalloc(size_t nmemb, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_srealloc(void *ptr, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_smemdup(const void *ptr, size_t size);
DREW_SYM_PUBLIC
void drew_mem_sfree(void *ptr);

DREW_SYM_PUBLIC
void *drew_mem_pmalloc(void *poolp, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_pcalloc(void *poolp, size_t nmemb, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_prealloc(void *poolp, void *ptr, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_pmemdup(void *poolp, const void *ptr, size_t size);
DREW_SYM_PUBLIC
void drew_mem_pfree(void *poolp, void *ptr);

DREW_SYM_PUBLIC
void *drew_mem_psmalloc(void *poolp, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_pscalloc(void *poolp, size_t nmemb, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_psrealloc(void *poolp, void *ptr, size_t size);
DREW_SYM_PUBLIC
void *drew_mem_psmemdup(void *poolp, const void *ptr, size_t size);
DREW_SYM_PUBLIC
void drew_mem_psfree(void *poolp, void *ptr);

DREW_SYM_PUBLIC
int drew_mem_pool_adjust(void *pool, int op, int flags, void *p);

#ifdef __cplusplus
}
#endif

#endif
