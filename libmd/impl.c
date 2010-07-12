#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <hash.h>
#include <plugin.h>

struct plugin_functbl {
	int (*info)(int, void *);
	void (*init)(void **);
	void (*update)(void *, const uint8_t *, size_t);
	void (*pad)(void *);
	void (*final)(void *, uint8_t *);
	void (*transform)(void *, void *, const uint8_t *);
};

struct plugin_info {
	const char *name;
	struct plugin_functbl *tbl;
};

#define PLUGIN_MD4 0
#define PLUGIN_MD5 1
#define PLUGIN_RMD160 2
#define PLUGIN_SHA1 3
#define PLUGIN_SHA256 4

static struct plugin_info plugins[] = {
	{"md4"},
	{"md5"},
	{"ripe160"},
	{"sha1"},
	{"sha256"}
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

		drew_loader_new(&ldr);

		for (i = 0; i < DIM(plugins); i++) {
			int id;
			const void *functbl;

			id = drew_loader_load_plugin(ldr, plugins[i].name, "./plugins");
			drew_loader_get_functbl(ldr, id, &functbl);
			plugins[i].tbl = (struct plugin_functbl *)functbl;
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
}

INTERFACE(MD4, MD4)
INTERFACE(MD5, MD5)
INTERFACE(RMD160, RMD160)
INTERFACE(SHA1, SHA1)
INTERFACE(SHA256, SHA256)
