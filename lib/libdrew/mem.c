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
	}
	else if ((res = posix_memalign(&p, mempool.pgsize, size))) {
		errno = res;
		goto err;
	}
	else if (clear)
		memset(p, 0, size);
	new = malloc(sizeof(struct allocation));
	if (!p || !new) {
		errno = ENOMEM;
		goto err;
	}
	new->next = mempool.alloc;
	new->block = 0;
	if (secure) {
#if ODD_MLOCK_OK-0
		new->block = size;
#else
		/* Assumes mempool.pgsize is a power of two. */
		uintptr_t mask = ~(mempool.pgsize - 1);
		new->block = (size + (mempool.pgsize - 1)) & mask;
#endif
		if (mlock(p, new->block))
			goto err;
	}
	new->mem = p;
	new->size = size;
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
	return drew_mem_free(ptr);
}

void drew_mem_free(void *ptr)
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

static void *do_realloc(void *ptr, void *new, size_t size)
{
	struct allocation *p;
	size_t oldsize = 0, min;
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

void *drew_mem_srealloc(void *ptr, size_t size)
{
	void *new;
	if (!ptr)
		return drew_mem_smalloc(size);
	if (!size) {
		drew_mem_free(ptr);
		return NULL;
	}
	new = drew_mem_smalloc(size);
	if (!new)
		return NULL;
	return do_realloc(ptr, new, size);
}

void *drew_mem_realloc(void *ptr, size_t size)
{
	void *new;
	if (!ptr)
		return drew_mem_malloc(size);
	if (!size) {
		drew_mem_free(ptr);
		return NULL;
	}
	new = drew_mem_malloc(size);
	if (!new)
		return NULL;
	return do_realloc(ptr, new, size);
}
