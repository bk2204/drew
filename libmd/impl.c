#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <hash.h>
#include <plugin.h>

struct plugin_info {
	const char *name;
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
	{"md4"},
	{"md5"},
	{"ripe160"},
	{"sha1"},
	{"sha256"},
	{"sha384"},
	{"sha512"}
};

static pthread_mutex_t drew_impl_libmd__mutex = PTHREAD_MUTEX_INITIALIZER;
static drew_loader_t *ldr = NULL;

#define DIM(x) (sizeof(x)/sizeof(x[0]))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

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

		drew_loader_new(&ldr);

		for (i = 0; i < DIM(plugins); i++) {
			int id;
			const void *functbl;

			id = drew_loader_load_plugin(ldr, plugins[i].name, "./plugins");
			drew_loader_get_functbl(ldr, id, &functbl);
			plugins[i].tbl = (drew_hash_functbl_t *)functbl;
		}
	}
	
	pthread_mutex_unlock(&drew_impl_libmd__mutex);
}

struct context {
	void *ctx;
};

#define CONCAT(prefix, suffix) prefix ## suffix
#define INTERFACE(prefix, name) \
\
void prefix ## Init(struct context *ctx) \
{ \
	drew_impl_libmd_init(); \
	(plugins[CONCAT(PLUGIN_, name)].tbl->init)(&ctx->ctx); \
} \
 \
void prefix ## Update(struct context *ctx, const uint8_t *data, size_t len) \
{ \
	(plugins[CONCAT(PLUGIN_, name)].tbl->update)(ctx->ctx, data, len); \
} \
 \
void prefix ## Pad(struct context *ctx) \
{ \
	(plugins[CONCAT(PLUGIN_, name)].tbl->pad)(ctx->ctx); \
} \
 \
void prefix ## Final(uint8_t *digest, struct context *ctx) \
{ \
	(plugins[CONCAT(PLUGIN_, name)].tbl->final)(ctx->ctx, digest); \
} \
 \
void prefix ## Transform(void *state, const uint8_t *block) \
{ \
	drew_impl_libmd_init(); \
	(plugins[CONCAT(PLUGIN_, name)].tbl->transform)(NULL, state, block); \
} \
 \
char *prefix ## End(struct context *ctx, char *buf) \
{ \
	const char *hex = "0123456789abcdef"; \
	uint8_t *data; \
	int size = 0; \
	int i; \
 \
	size = (plugins[CONCAT(PLUGIN_, name)].tbl->info)(DREW_HASH_SIZE, ctx->ctx); \
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
char *prefix ## Data(const uint8_t *data, size_t len, char *buf) \
{ \
	struct context ctx; \
 \
	prefix ## Init(&ctx); \
	prefix ## Update(&ctx, data, len); \
	return prefix ## End(&ctx, buf); \
} \
char *prefix ## FileChunk(const char *filename, char *buf, off_t offset, \
		off_t length) \
{ \
	int fd = -1; \
	struct context ctx; \
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
char *prefix ## File(const char *filename, char *buf) \
{ \
	return prefix ## FileChunk(filename, buf, 0, 0); \
}

INTERFACE(MD4, MD4)
INTERFACE(MD5, MD5)
INTERFACE(RMD160, RMD160)
INTERFACE(SHA1, SHA1)
INTERFACE(SHA256, SHA256)
INTERFACE(SHA384, SHA384)
INTERFACE(SHA512, SHA512)
