#ifndef DREW_MEM_H
#define DREW_MEM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *drew_mem_malloc(size_t size);
void *drew_mem_calloc(size_t nmemb, size_t size);
void *drew_mem_realloc(void *ptr, size_t size);
void *drew_mem_memdup(const void *ptr, size_t size);
void drew_mem_free(void *ptr);

void *drew_mem_smalloc(size_t size);
void *drew_mem_scalloc(size_t nmemb, size_t size);
void *drew_mem_srealloc(void *ptr, size_t size);
void *drew_mem_smemdup(const void *ptr, size_t size);
void drew_mem_sfree(void *ptr);

#ifdef __cplusplus
}
#endif

#endif
