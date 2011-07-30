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
