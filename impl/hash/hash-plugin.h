#ifndef HASH_PLUGIN_H
#define HASH_PLUGIN_H

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <errno.h>
#include <string.h>

#include <hash.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <plugin.h>

struct plugin_functbl {
	int (*info)(int, void *);
	void (*init)(void **);
	void (*update)(void *, const uint8_t *, size_t);
	void (*pad)(void *);
	void (*final)(void *, uint8_t *);
	void (*transform)(void *, void *, const uint8_t *);
};

#define PLUGIN_FUNCTBL(prefix, info, init, update, pad, final, transform) \
\
static struct plugin_functbl prefix ## functbl = { \
	info, init, update, pad, final, transform \
};

struct plugin {
	const char *name;
	struct plugin_functbl *functbl;
};

#define PLUGIN_DATA_START() static struct plugin plugin_data[] = {
#define PLUGIN_DATA_END() };
#define PLUGIN_DATA(prefix, name) { name, & prefix ## functbl },

#define PLUGIN_INFO(name) static const char *pname = name
#define PLUGIN_INTERFACE() \
\
int drew_plugin_info(void *ldr, int op, int id, void *p) \
{ \
\
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]); \
	if (id < 0 || id >= nplugins) \
		return -EINVAL; \
	switch (op) { \
		case DREW_LOADER_LOOKUP_NAME: \
			return 0; \
		case DREW_LOADER_GET_NPLUGINS: \
			return nplugins; \
		case DREW_LOADER_GET_TYPE: \
			return 1; \
		case DREW_LOADER_GET_FUNCTBL_SIZE: \
			return sizeof(struct plugin_functbl); \
		case DREW_LOADER_GET_FUNCTBL: \
			memcpy(p, plugin_data[id].functbl, sizeof(struct plugin_functbl)); \
			return 0; \
		default: \
			return -EINVAL; \
	} \
}

#ifdef __cplusplus
}
#endif

#endif
