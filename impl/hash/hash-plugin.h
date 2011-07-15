#ifndef HASH_PLUGIN_H
#define HASH_PLUGIN_H

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <drew/plugin.h>
#include <drew/hash.h>

#define PLUGIN_FUNCTBL(prefix, info, init, update, updatefast, pad, final, transform, test, fini, clone, reset) \
\
static drew_hash_functbl_t prefix ## functbl = { \
	info, init, clone, reset, fini, update, updatefast, pad, final, transform, test \
};

struct plugin {
	const char *name;
	drew_hash_functbl_t *functbl;
};

#define PLUGIN_DATA_START() static struct plugin plugin_data[] = {
#define PLUGIN_DATA_END() };
#define PLUGIN_DATA(prefix, name) { name, & prefix ## functbl },

#define PLUGIN_INFO(name) static const char *pname = name
#define PLUGIN_INTERFACE(x) \
\
EXPORT() \
int DREW_PLUGIN_NAME(x)(void *ldr, int op, int id, void *p) \
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
			return sizeof(drew_hash_functbl_t); \
		case DREW_LOADER_GET_FUNCTBL: \
			memcpy(p, plugin_data[id].functbl, sizeof(drew_hash_functbl_t)); \
			return 0; \
		case DREW_LOADER_GET_NAME_SIZE: \
			return strlen(plugin_data[id].name) + 1; \
		case DREW_LOADER_GET_NAME: \
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1); \
			return 0; \
		default: \
			return -EINVAL; \
	} \
} \
UNEXPORT()

#ifdef __cplusplus
}
#endif

#endif
