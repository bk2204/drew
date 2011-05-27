#include "internal.h"
#define DREW_IN_BUILD_DREW_C
#include <drew/drew.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Set if the plugin has been properly loaded.
#define FLAG_PLUGIN_OK		1

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
		const char *path, library_t **libp)
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
	*libp = lib;
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

/* Load all the info from the library, including all plugin-specific
 * information.
 */
static int load_library_info(drew_loader_t *ldr, library_t *lib)
{
	int err = -DREW_ERR_ENUMERATION;
	int offset = ldr->nplugins;
	plugin_t *p;

	lib->nplugins = lib->api(ldr, DREW_LOADER_LOOKUP_NAME, 0, NULL);
	if (lib->nplugins < 0)
		goto out;

	err = -ENOMEM;
	p = realloc(ldr->lib, sizeof(*p) * (ldr->nplugins + lib->nplugins));
	if (!p)
		goto out;
	ldr->nplugins += lib->nplugins;
	ldr->plugins = p;

	p += offset;
	for (int i = 0; i < lib->nplugins; i++, p++) {
		int tblsize, namesize, mdsize;

		memset(p, 0, sizeof(*p));

		err = -DREW_ERR_ENUMERATION;
		p->type = lib->api(ldr, DREW_LOADER_GET_TYPE, i, NULL);
		if (p->type < 0)
			goto out;

		tblsize = lib->api(ldr, DREW_LOADER_GET_FUNCTBL_SIZE, i, NULL);
		if (tblsize <= 0 || tblsize % sizeof(void *))
			goto out;

		// Includes terminating NUL.
		namesize = lib->api(ldr, DREW_LOADER_GET_NAME_SIZE, i, NULL);
		if (namesize <= 0)
			goto out;

		// Metadata are optional, so don't error out if they're not available.
		mdsize = lib->api(ldr, DREW_LOADER_GET_NAME_SIZE, i, NULL);
		if (mdsize < 0)
			mdsize = 0;

		err = -ENOMEM;
		p->functbl = malloc(tblsize);
		if (!p->functbl)
			goto out;

		p->metadata = malloc(mdsize);
		if (mdsize && !p->metadata)
			goto out;

		p->name = malloc(namesize);
		if (!p->name)
			goto out;

		err = -DREW_ERR_FUNCTION;
		if (lib->api(ldr, DREW_LOADER_GET_FUNCTBL, i, p->functbl))
			goto out;

		err = -DREW_ERR_ENUMERATION;
		if (lib->api(ldr, DREW_LOADER_GET_NAME, i, p->name))
			goto out;
		p->name[namesize-1] = '\0'; // Just in case.

		if (mdsize)
			if (lib->api(ldr, DREW_LOADER_GET_METADATA, id, p->metadata))
				goto out;
		p->nmetadata = mdsize / sizeof(drew_metadata_t);

		p->lib = lib;
		p->id = offset + i;
		p->flags = FLAG_PLUGIN_OK;
	}
	err = 0;
out:
	if (err) {
		free(p->functbl);
		free(p->name);
		free(p->metadata);
	}
	return err;
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
	int err = 0;
	library_t *lib;

	if ((err = load_library(ldr, plugin, path, &lib)))
		return err;
	err = load_library_info(ldr, lib);
	return err;
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

