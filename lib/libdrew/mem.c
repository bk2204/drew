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
/* This is a memory allocator for Drew.  It uses the system-provided primitives
 * to implement secure memory (that is locked and cannot be swapped), as well as
 * providing a free function that will zero memory from the Drew allocator
 * before freeing it.
 *
 * It is designed so that the free function provided works for all memory
 * obtained from the system malloc and friends; the only consequence is that it
 * is not zeroed (since we do not know how big the allocation was).
 *
 * Secure memory is allocated using posix_memalign because although Linux allows
 * us to map arbitrary portions (non-page-aligned and non-page size) of memory,
 * other systems do not, and so by ensuring allocations are on a page size
 * boundary, we don't have to take extra care to ensure we don't accidentally
 * unlock a page of memory that is also in use by another secure chunk.  This
 * makes small allocations less efficient and potentially wastes some memory,
 * but it essentially guarantees better performance due to significantly less
 * overhead.
 */

#include "internal.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <drew/mem.h>

#if defined(__linux__)
#define ODD_MLOCK_OK	1
#else
#define ODD_MLOCK_OK	0
#endif

#if defined(DREW_MEM_ALWAYS_ZERO)
#define ALWAYS_ZERO 1
#else
#define ALWAYS_ZERO 0
#endif

struct allocation {
	struct allocation *next;
	void *mem;
	size_t size;
	size_t block;
};

struct pool {
	pthread_mutex_t mutex;
	size_t pgsize;
	int inited;
	int flags;
	struct allocation *alloc;
};

static struct pool mempool = {
	PTHREAD_MUTEX_INITIALIZER,
#if defined(PAGESIZE)
	PAGESIZE,
#elif defined(PAGE_SIZE)
	PAGE_SIZE,
#else
	0,
#endif
	0,
	0,
	0
};

/* This can only be called under lock. */
static inline void init_pool(void)
{
#if !defined(PAGESIZE) && !defined(PAGE_SIZE)
	if (unlikely(!mempool.inited)) {
		if (!mempool.pgsize) {
			long val = sysconf(_SC_PAGESIZE);
			mempool.pgsize = (val <= 0) ? 4096 : val;
		}
		mempool.inited = 1;
	}
#endif
}

static inline struct allocation *create_entry(void *p, size_t size, int secure)
{
	struct allocation *new;
	if (!p)
		return NULL;
	new = malloc(sizeof(struct allocation));
	if (!new)
		return NULL;
	new->next = mempool.alloc;
	new->size = size;
	new->block = 0;
	new->mem = p;
	if (secure) {
		if (ODD_MLOCK_OK)
			new->block = size;
		else {
			/* Assumes mempool.pgsize is a power of two. */
			uintptr_t mask = ~(mempool.pgsize - 1);
			new->block = (size + (mempool.pgsize - 1)) & mask;
		}
	}
	return new;
}

/* This can only be called under lock.
 *
 * Regardless of what the system malloc does, we always return NULL for a
 * zero-sized allocation.
 */
static inline void *do_allocate(size_t size, int secure, int clear)
{
	int res = 0;
	void *p = NULL;
	struct allocation *new = NULL;
	if (!size)
		return NULL;
	if (!secure || ODD_MLOCK_OK) {
		if (clear)
			p = calloc(1, size);
		else
			p = malloc(size);
		if (!p) {
			errno = ENOMEM;
			goto err;
		}
	}
	else if ((res = posix_memalign(&p, mempool.pgsize, size))) {
		errno = res;
		goto err;
	}
	else if (clear)
		memset(p, 0, size);
	// p is guaranteed to be non-NULL here and zeroed if need be.
	if (secure || ALWAYS_ZERO)
		if (!(new = create_entry(p, size, secure)))
			goto err;
	if (secure && !(mempool.flags & DREW_MEM_SECMEM_NO_LOCK) &&
			mlock(p, new->block) && !(mempool.flags & DREW_MEM_SECMEM_FAIL_OK))
		goto err;
	if (new)
		mempool.alloc = new;
	return p;
err:
	free(p);
	free(new);
	return NULL;
}

static inline void *allocate(size_t size, int secure, int clear)
{
	void *p;
	if (!size)
		return NULL;
	LOCK(&mempool);
	init_pool();
	p = do_allocate(size, secure, clear);
	UNLOCK(&mempool);
	return p;
}

int drew_mem_pool_adjust(void *pool, int op, int flags, void *p)
{
	if (pool)
		return -DREW_ERR_INVALID;
	if (op != DREW_MEM_SECMEM)
		return -DREW_ERR_INVALID;
	LOCK(&mempool);
	init_pool();
	mempool.flags = flags;
	UNLOCK(&mempool);
	return 0;
}

void *drew_mem_memdup(const void *ptr, size_t size)
{
	void *p = allocate(size, 0, 0);
	if (p)
		memcpy(p, ptr, size);
	return p;
}

void *drew_mem_smemdup(const void *ptr, size_t size)
{
	void *p = allocate(size, 1, 0);
	if (p)
		memcpy(p, ptr, size);
	return p;
}

void *drew_mem_malloc(size_t size)
{
	return allocate(size, 0, 0);
}

void *drew_mem_smalloc(size_t size)
{
	return allocate(size, 1, 0);
}

void *drew_mem_calloc(size_t nmemb, size_t size)
{
	return allocate(nmemb * size, 0, 1);
}

void *drew_mem_scalloc(size_t nmemb, size_t size)
{
	return allocate(nmemb * size, 1, 1);
}

void drew_mem_sfree(void *ptr)
{
	struct allocation *p, *prev;
	if (!ptr)
		return;
	LOCK(&mempool);
	init_pool();
	for (prev = p = mempool.alloc; p; prev = p, p = p->next) {
		if (ptr == p->mem) {
			memset(ptr, 0, p->size);
			if (p->block)
				munlock(p->mem, p->block);
			if (mempool.alloc == p)
				mempool.alloc = p->next;
			else
				prev->next = p->next;
			free(p);
			break;
		}
	}
	free(ptr);
	UNLOCK(&mempool);
}

void drew_mem_free(void *ptr)
{
	if (ALWAYS_ZERO)
		drew_mem_sfree(ptr);
	else
		free(ptr);
}

static inline void *do_realloc(void *ptr, void *new, size_t size, int secure)
{
	struct allocation *p;
	size_t oldsize = 0, min = 0;
	if (secure || ALWAYS_ZERO) {
		LOCK(&mempool);
		init_pool();
			for (p = mempool.alloc; p; p = p->next) {
				if (ptr == p->mem) {
					oldsize = p->size;
					break;
				}
			}
		UNLOCK(&mempool);
		if (!oldsize) {
			// Someone passed us a pointer we didn't allocate.
			free(new);
			errno = EINVAL;
			return NULL;
		}
		min = MIN(size, oldsize);
		memcpy(new, ptr, min);
		if (size > oldsize)
			memset(new+oldsize, 0, size-oldsize);
		drew_mem_free(ptr);
		return new;
	}
	return realloc(ptr, size);
}

void *drew_mem_srealloc(void *ptr, size_t size)
{
	void *new = NULL;
	if (!ptr)
		return drew_mem_smalloc(size);
	if (!size) {
		drew_mem_sfree(ptr);
		return NULL;
	}
	new = drew_mem_smalloc(size);
	if (!new)
		return NULL;
	return do_realloc(ptr, new, size, 1);
}

void *drew_mem_realloc(void *ptr, size_t size)
{
	void *new = NULL;
	if (!ptr)
		return drew_mem_malloc(size);
	if (!size) {
		drew_mem_free(ptr);
		return NULL;
	}
	if (ALWAYS_ZERO) {
		new = drew_mem_malloc(size);
		if (!new)
			return NULL;
	}
	return do_realloc(ptr, new, size, 0);
}
