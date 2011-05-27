#include "internal.h"
#define DREW_IN_BUILD_DREW_C
#include <drew/drew.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*plugin_api_t)(void *, int, int, void *);

typedef void *functbl_t;
typedef void *handle_t;


// There is one of these per drew_plugin_info interface.
typedef struct {
	char *name;
	char *path;
	plugin_api_t api;
	handle_t handle;
	int nplugins;
} library_t;

// There is one of these per plugin (that is, item with a functbl).
typedef struct {
	char *name;
	library_t *lib;
	functbl_t functbl;
	int id;
	int type;
	int flags;
	int nmetadata;
	drew_metadata_t *metadata;
} plugin_t;

struct drew_loader_s {
	int version;
	int flags;
	int nlibs;
	library_t *lib;
	int nplugins;
	plugin_t *plugin;
};

static handle_t open_library(const char *pathname)
{
	return dlopen(pathname, RTLD_LAZY|RTLD_LOCAL);
}

static void close_library(handle_t handle)
{
	dlclose(handle);
}

static plugin_api_t get_api(handle_t handle)
{
	return dlsym(handle, "drew_plugin_info");
}

/* Allocate a library table entry and load the library information from it.  If
 * library is NULL, try to load the current executable instead.
 */
static int load_library(drew_loader_t *ldr, const char *library,
		const char *path)
{
	int err = 0;
	library_t *p, *lib;
	p = realloc(ldr->lib, sizeof(*p) * (ldr->nlibs + 1));
	if (!p)
		return -ENOMEM;
	ldr->lib = p;
	lib = &ldr->lib[ldr->nlibs];
	ldr->nlibs++;

	if (!library) {
		err = -DREW_ERR_RESOLUTION;
		if (!(lib->handle = open_library(NULL)))
			goto out;
		lib->name = strdup("<internal>");
		lib->path = NULL;
	}
	else {
		size_t sz = strlen(library) + 1 + strlen(path) + 1;
		err = -ENOMEM;
		if (!(lib->path = malloc(sz)))
			goto out;
		err = -DREW_ERR_BUG;
		if (snprintf(lib->path, sz, "%s/%s", path, library) >= sz)
			goto out;
		// TODO: query this from the library.
		lib->name = strdup(library);
		err = -DREW_ERR_RESOLUTION;
		if (!(lib->handle = open_library(lib->path)))
			goto out;
	}
	err = -DREW_ERR_ENUMERATION;
	if (!(lib->api = get_api(lib->handle)))
		goto out;

	err = 0;
out:
	if (err) {
		if (lib->handle)
			close_library(lib->handle);
		free(lib->name);
		free(lib->path);
		ldr->nlibs--;
	}
	return err;
}

static int load_library_info(drew_loader_t *ldr, library_t *lib)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_new(drew_loader_t **ldrp)
{
	drew_loader_t *ldr;

	if (!ldrp)
		return -DREW_ERR_INVALID;

	if (!(ldr = malloc(sizeof(*ldr))))
		return -ENOMEM;

	memset(ldr, 0, sizeof(*ldr));

	*ldrp = ldr;

	return 0;
}

int drew_loader_free(drew_loader_t **ldrp)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_load_plugin(drew_loader_t *ldr, const char *plugin,
		const char *path)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_get_nplugins(const drew_loader_t *ldr, int id)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_get_type(const drew_loader_t *ldr, int id)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_get_functbl(const drew_loader_t *ldr, int id, const void **tbl)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_get_algo_name(const drew_loader_t *ldr, int id,
		const char **namep)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_lookup_by_name(const drew_loader_t *ldr, const char *name,
		int start, int end)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_lookup_by_type(const drew_loader_t *ldr, int type, int start,
		int end)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_loader_get_metadata(const drew_loader_t *ldr, int id, int item,
		drew_metadata_t *meta)
{
	return -DREW_ERR_NOT_IMPL;
}

