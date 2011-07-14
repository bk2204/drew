#ifndef DREW_MEM_H
#define DREW_MEM_H

void *drew_mem_malloc(size_t size);
void *drew_mem_calloc(size_t nmemb, size_t size);
void *drew_mem_realloc(void *ptr, size_t size);
void drew_mem_free(void *ptr);

void *drew_mem_smalloc(size_t size);
void *drew_mem_scalloc(size_t nmemb, size_t size);
void *drew_mem_srealloc(void *ptr, size_t size);
void drew_mem_sfree(void *ptr);

#endif
