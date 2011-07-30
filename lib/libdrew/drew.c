/*-
 * Copyright © 2010-2011 brian m. carlson
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

#include "internal.h"
#include <drew/drew.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
	int functblsize;
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
#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 5
	// FIXME: discover why Debian bug #631531 occurs and remove this.
	return dlopen(pathname, RTLD_NOW|RTLD_LOCAL);
#else
	return dlopen(pathname, RTLD_LAZY|RTLD_LOCAL);
#endif
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
	plugin_t *p = NULL;

	lib->nplugins = lib->api(ldr, DREW_LOADER_GET_NPLUGINS, 0, NULL);
	if (lib->nplugins < 0)
		goto out;

	err = -ENOMEM;
	p = realloc(ldr->plugin, sizeof(*p) * (ldr->nplugins + lib->nplugins + 1));
	if (!p)
		goto out;
	ldr->nplugins += lib->nplugins;
	ldr->plugin = p;

	p += offset;
	for (int i = 0; i < lib->nplugins; i++, p++) {
		int namesize, mdsize;

		memset(p, 0, sizeof(*p));

		err = -DREW_ERR_ENUMERATION;
		p->type = lib->api(ldr, DREW_LOADER_GET_TYPE, i, NULL);
		if (p->type < 0)
			goto out;

		p->functblsize = lib->api(ldr, DREW_LOADER_GET_FUNCTBL_SIZE, i, NULL);
		if (p->functblsize <= 0 || p->functblsize % sizeof(void *))
			goto out;

		// Includes terminating NUL.
		namesize = lib->api(ldr, DREW_LOADER_GET_NAME_SIZE, i, NULL);
		if (namesize <= 0)
			goto out;

		// Metadata are optional, so don't error out if they're not available.
		mdsize = lib->api(ldr, DREW_LOADER_GET_METADATA_SIZE, i, NULL);
		if (mdsize < 0)
			mdsize = 0;

		err = -ENOMEM;
		p->functbl = malloc(p->functblsize);
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
			if (lib->api(ldr, DREW_LOADER_GET_METADATA, i, p->metadata))
				goto out;
		p->nmetadata = mdsize / sizeof(drew_metadata_t);

		p->lib = lib;
		p->id = offset + i;
		p->flags = FLAG_PLUGIN_OK;
	}
	err = 0;
out:
	if (err && p) {
		free(p->functbl);
		free(p->name);
		free(p->metadata);
	}
	return err ? err : offset;
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
	drew_loader_t *ldr;

	if (!ldrp)
		return -DREW_ERR_INVALID;

	ldr = *ldrp;

	for (int i = 0; i < ldr->nlibs; i++) {
		free(ldr->lib[i].name);
		free(ldr->lib[i].path);
		close_library(ldr->lib[i].handle);
	}
	free(ldr->lib);

	for (int i = 0; i < ldr->nplugins; i++) {
		if (!(ldr->plugin[i].flags & FLAG_PLUGIN_OK))
			continue;
		free(ldr->plugin[i].name);
		free(ldr->plugin[i].functbl);
		free(ldr->plugin[i].metadata);
	}
	free(ldr->plugin);
	free(ldr);

	*ldrp = NULL;
	return 0;
}

int drew_loader_load_plugin(drew_loader_t *ldr, const char *plugin,
		const char *path)
{
	int err = 0;
	library_t *lib;

	if (plugin && !path) {
		int npaths = drew_loader_get_search_path(ldr, 0, NULL), i;
		for (i = 0; i < npaths; i++) {
			drew_loader_get_search_path(ldr, i, &path);
			if (!load_library(ldr, plugin, path, &lib))
				break;
		}
		if (i == npaths)
			return -DREW_ERR_RESOLUTION;
	}
	else if ((err = load_library(ldr, plugin, path, &lib)))
		return err;
	return load_library_info(ldr, lib);
}

static inline bool is_valid_id(const drew_loader_t *ldr, int id)
{
	if (!ldr)
		return false;
	if (id < 0)
		return false;
	if (id >= ldr->nplugins)
		return false;
	if (!(ldr->plugin[id].flags & FLAG_PLUGIN_OK))
		return false;
	return true;
}

/* This function queries the number of plugins in the library which contains the
 * plugin with ID id.  As a special case, if id is -1, return the total number
 * of plugins loaded.
 */
int drew_loader_get_nplugins(const drew_loader_t *ldr, int id)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (id == -1)
		return ldr->nplugins;
	if (!is_valid_id(ldr, id))
		return -DREW_ERR_INVALID;

	return ldr->plugin[id].lib->nplugins;
}

int drew_loader_get_type(const drew_loader_t *ldr, int id)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (!is_valid_id(ldr, id))
		return -DREW_ERR_INVALID;

	return ldr->plugin[id].type;
}

int drew_loader_get_functbl(const drew_loader_t *ldr, int id, const void **tbl)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (!is_valid_id(ldr, id))
		return -DREW_ERR_INVALID;

	if (tbl)
		*tbl = ldr->plugin[id].functbl;
	return ldr->plugin[id].functblsize;
}

int drew_loader_get_algo_name(const drew_loader_t *ldr, int id,
		const char **namep)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (!is_valid_id(ldr, id))
		return -DREW_ERR_INVALID;

	*namep = ldr->plugin[id].name;
	return 0;
}

int drew_loader_lookup_by_name(const drew_loader_t *ldr, const char *name,
		int start, int end)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (end == -1)
		end = ldr->nplugins;

	for (int i = start; i < end; i++) {
		if (!is_valid_id(ldr, i))
			continue;
		if (!strcmp(ldr->plugin[i].name, name))
			return i;
	}

	return -DREW_ERR_NONEXISTENT;
}

int drew_loader_lookup_by_type(const drew_loader_t *ldr, int type, int start,
		int end)
{
	if (!ldr)
		return -DREW_ERR_INVALID;
	if (end == -1)
		end = ldr->nplugins;

	for (int i = start; i < end; i++) {
		if (!is_valid_id(ldr, i))
			continue;
		if (ldr->plugin[i].type == type)
			return i;
	}

	return -DREW_ERR_NONEXISTENT;
}

int drew_loader_get_search_path(const drew_loader_t *ldr, int num,
		const char **p)
{
	const char *paths[] = {
		DREW_SEARCH_PATH
	};

	if (num < 0)
		return -DREW_ERR_INVALID;
	if (num > DIM(paths))
		return -DREW_ERR_NONEXISTENT;
	if (p)
		*p = paths[num];
	return DIM(paths);
}

/* This will eventually provide an rdf:seeAlso to an .rdf file with the same
 * basename as the plugin, and potentially provide some metadata that may
 * already be available, such as algorithm information and so forth.
 */
static int special_metadata(const drew_loader_t *ldr, int id,
		int item, drew_metadata_t *meta)
{
	if (item > 0)
		return -DREW_ERR_NONEXISTENT;

	const char *path = ldr->plugin[id].lib->path;
	if (!path)
		return -DREW_ERR_NONEXISTENT;
	const char *prefix = "file://";
	const size_t prefixlen = strlen(prefix);
	struct stat st;
	const char *suffix = ".rdf";
	const size_t suffixlen = strlen(suffix);
	size_t pathlen = strlen(path);
	char *rdfpath = malloc(pathlen + suffixlen + 1);

	strncpy(rdfpath, ldr->plugin[id].lib->path, pathlen);
	strncpy(rdfpath+pathlen, suffix, suffixlen + 1);

	size_t sz = strlen(rdfpath);

	if (!stat(rdfpath, &st)) {
		if (meta) {
			meta->version = 0;
			meta->predicate =
				strdup("http://www.w3.org/2000/01/rdf-schema#seeAlso");
			meta->type = DREW_LOADER_MD_URI;
			meta->object = malloc(strlen(prefix) + strlen(rdfpath) + 1);
			strncpy(meta->object, prefix, prefixlen);
			strncpy(meta->object+prefixlen, rdfpath, sz+1);
		}
		free(rdfpath);
		return 0;
	}
	free(rdfpath);
	return -DREW_ERR_NONEXISTENT;
}

int drew_loader_get_metadata(const drew_loader_t *ldr, int id, int item,
		drew_metadata_t *meta)
{
	drew_metadata_t md;
	int retval = 0;

	if (!ldr)
		return -DREW_ERR_INVALID;

	if (!is_valid_id(ldr, id))
		return -DREW_ERR_NONEXISTENT;

	if (item == -1) {
		retval = special_metadata(ldr, id,
				(item - ldr->plugin[id].nmetadata), NULL);
		
		return ldr->plugin[id].nmetadata + (retval == 0);
	}

	if (item < 0)
		return -DREW_ERR_INVALID;
	
	if (item < ldr->plugin[id].nmetadata) {
		memcpy(meta, ldr->plugin[id].metadata + item, sizeof(*meta));
		meta->predicate = strdup(meta->predicate);
		meta->object = strdup(meta->object);
		return 0;
	}
	else {
		memset(&md, 0, sizeof(md));
		retval = special_metadata(ldr, id,
				(item - ldr->plugin[id].nmetadata), &md);
		if (retval < 0) {
			free(md.predicate);
			free(md.object);
			return -DREW_ERR_NONEXISTENT;
		}
		memcpy(meta, &md, sizeof(*meta));
		return 0;
	}

	return -DREW_ERR_NONEXISTENT;
}
