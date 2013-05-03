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
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/plugin.h>

#include "util.h"

struct plugin_info {
	const char *name;
	const char *algo;
	drew_hash_functbl_t *tbl;
};

#define PLUGIN_MD4 0
#define PLUGIN_MD5 1
#define PLUGIN_RMD160 2
#define PLUGIN_SHA1 3
#define PLUGIN_SHA256 4
#define PLUGIN_SHA384 5
#define PLUGIN_SHA512 6

static struct plugin_info plugins[] = {
	{"md4", "MD4"},
	{"md5", "MD5"},
	{"ripe160", "RIPEMD-160"},
	{"sha1", "SHA-1"},
	{"sha256", "SHA-256"},
	{"sha384", "SHA-384"},
	{"sha512", "SHA-512"}
};

static pthread_mutex_t drew_impl_libmd__mutex = PTHREAD_MUTEX_INITIALIZER;
static drew_loader_t *ldr = NULL;

#define DIM(x) (sizeof(x)/sizeof(x[0]))

/* This function takes care of loading the plugins and other data necessary for
 * runtime.  It is protected by a mutex.  When the mutex is unlocked, the data
 * in the plugins array is considered const.  Because it is assumed that you
 * will be calling the functions in the right order, this function is not called
 * from functions that must have a valid hash context.
 */
static void drew_impl_libmd_init(void)
{
	pthread_mutex_lock(&drew_impl_libmd__mutex);

	if (!ldr) {
		size_t i;

		ldr = drew_loader_new();
		drew_loader_load_plugin(ldr, NULL, NULL);

		for (i = 0; i < DIM(plugins); i++) {
			int id;
			const void *functbl;

			drew_loader_load_plugin(ldr, plugins[i].name, "./plugins");
			id = drew_loader_lookup_by_name(ldr, plugins[i].algo, 0, -1);
			drew_loader_get_functbl(ldr, id, &functbl);
			plugins[i].tbl = (drew_hash_functbl_t *)functbl;
		}
	}
	
	pthread_mutex_unlock(&drew_impl_libmd__mutex);
}

#define CONCAT(prefix, suffix) prefix ## suffix

#ifdef FEATURE_ALIAS
#define ALIAS(prefix, realprefix, name) \
DREW_SYM_PUBLIC \
void prefix ## Init(drew_hash_t *ctx) ALIAS_FOR(realprefix ## Init); \
DREW_SYM_PUBLIC \
void prefix ## Update(drew_hash_t *ctx, const uint8_t *data, size_t len) \
	 ALIAS_FOR(realprefix ## Update); \
DREW_SYM_PUBLIC \
void prefix ## Pad(drew_hash_t *ctx) ALIAS_FOR(realprefix ## Pad); \
DREW_SYM_PUBLIC \
void prefix ## Final(uint8_t *digest, drew_hash_t *ctx) \
	 ALIAS_FOR(realprefix ## Final); \
DREW_SYM_PUBLIC \
char *prefix ## End(drew_hash_t *ctx, char *buf) \
	 ALIAS_FOR(realprefix ## End); \
DREW_SYM_PUBLIC \
char *prefix ## Data(const uint8_t *data, size_t len, char *buf) \
	 ALIAS_FOR(realprefix ## Data); \
DREW_SYM_PUBLIC \
char *prefix ## FileChunk(const char *filename, char *buf, off_t offset, \
		off_t length) ALIAS_FOR(realprefix ## FileChunk); \
DREW_SYM_PUBLIC \
char *prefix ## File(const char *filename, char *buf) \
	 ALIAS_FOR(realprefix ## File);
#else
#define ALIAS(prefix, realprefix, name) INTERFACE(prefix, name)
#endif

#define INTERFACE(prefix, name) \
\
DREW_SYM_PUBLIC \
void prefix ## Init(drew_hash_t *ctx) \
{ \
	drew_impl_libmd_init(); \
	(plugins[CONCAT(PLUGIN_, name)].tbl->init)(ctx, 0, NULL, NULL); \
} \
 \
DREW_SYM_PUBLIC \
void prefix ## Update(drew_hash_t *ctx, const uint8_t *data, size_t len) \
{ \
	(ctx->functbl->update)(ctx, data, len); \
} \
 \
DREW_SYM_PUBLIC \
void prefix ## Pad(drew_hash_t *ctx) \
{ \
	(ctx->functbl->pad)(ctx); \
} \
 \
DREW_SYM_PUBLIC \
void prefix ## Final(uint8_t *digest, drew_hash_t *ctx) \
{ \
	int size; \
	size = (plugins[CONCAT(PLUGIN_, name)].tbl->info2)(ctx, \
			DREW_HASH_SIZE_CTX, NULL, NULL); \
	(ctx->functbl->final)(ctx, digest, size, 0); \
} \
 \
DREW_SYM_PUBLIC \
char *prefix ## End(drew_hash_t *ctx, char *buf) \
{ \
	const char *hex = "0123456789abcdef"; \
	uint8_t *data; \
	int size = 0; \
	int i; \
 \
	size = (plugins[CONCAT(PLUGIN_, name)].tbl->info2)(ctx, \
			DREW_HASH_SIZE_CTX, NULL, NULL); \
	data = malloc(size); \
	if (!data) \
		goto errout; \
	prefix ## Final(data, ctx); \
	if (!buf) \
		buf = malloc(size * 2 + 1); \
	if (!buf) \
		goto errout; \
 \
	for (i = 0; i < size; i++) { \
		buf[(i*2)  ] = hex[data[i]>>4]; \
		buf[(i*2)+1] = hex[data[i]&0xf]; \
	} \
	buf[size * 2] = 0; \
 \
	free(data); \
	return buf; \
errout: \
	free(data); \
	return NULL; \
} \
 \
DREW_SYM_PUBLIC \
char *prefix ## Data(const uint8_t *data, size_t len, char *buf) \
{ \
	drew_hash_t ctx; \
 \
	prefix ## Init(&ctx); \
	prefix ## Update(&ctx, data, len); \
	return prefix ## End(&ctx, buf); \
} \
DREW_SYM_PUBLIC \
char *prefix ## FileChunk(const char *filename, char *buf, off_t offset, \
		off_t length) \
{ \
	int fd = -1; \
	drew_hash_t ctx; \
 \
	if (offset < 0) \
		offset = 0; \
	if (length <= 0) \
		length = -1; \
 \
	if ((fd = open(filename, O_RDONLY)) < 0) \
		return NULL; \
	if (lseek(fd, SEEK_SET, offset) < 0) \
		goto errout; \
 \
	prefix ## Init(&ctx); \
 \
	while (length) { \
		uint8_t data[512]; \
		ssize_t retval; \
		size_t nbytes; \
 \
		nbytes = (length < 0) ? sizeof(data) : MIN(length, sizeof(data)); \
 \
		if ((retval = read(fd, data, nbytes)) < 0) \
			goto errout; \
		if (retval == 0) \
			break; \
		length -= retval; \
		prefix ## Update(&ctx, data, retval); \
 \
	} \
	close(fd); \
	return prefix ## End(&ctx, buf); \
errout: \
	close(fd); \
	return NULL; \
} \
DREW_SYM_PUBLIC \
char *prefix ## File(const char *filename, char *buf) \
{ \
	return prefix ## FileChunk(filename, buf, 0, 0); \
}

INTERFACE(MD4, MD4)
INTERFACE(MD5, MD5)
INTERFACE(RMD160, RMD160)
ALIAS(RIPEMD160_, RMD160, RMD160)
INTERFACE(SHA1, SHA1)
ALIAS(SHA1_, SHA1, SHA1)
INTERFACE(SHA256, SHA256)
ALIAS(SHA256_, SHA256, SHA256)
INTERFACE(SHA384, SHA384)
INTERFACE(SHA512, SHA512)
