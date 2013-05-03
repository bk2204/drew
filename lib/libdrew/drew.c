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

#include <glib-2.0/gmodule.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gprintf.h>

// Set if the plugin has been properly loaded.
#define FLAG_PLUGIN_OK		1
// Set if the plugin contains no implementations.
#define FLAG_PLUGIN_DUMMY	2

typedef int (*plugin_api_t)(void *, int, int, void *);

typedef void *functbl_t;
typedef GModule *handle_t;

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

// We use a GRWLock here because after setup, the lock will be essentially
// uncontended assuming nobody tries to load more plugins.
struct _DrewLoader {
	int version;
	int flags;
	int nlibs;
	library_t *lib;
	int nplugins;
	plugin_t *plugin;
	gint ref_count;
	GRWLock lock;
};

struct _DrewLoaderClass {
	GObjectClass parent_class;
};

static handle_t open_library(const char *pathname)
{
	return g_module_open(pathname, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
}

static void close_library(handle_t handle)
{
	g_module_close(handle);
}

static plugin_api_t get_api(handle_t handle)
{
	plugin_api_t p = NULL;
	return g_module_symbol(handle, "drew_plugin_info", (gpointer *)&p) ?
		p : NULL;
}

/* Allocate a library table entry and load the library information from it.  If
 * library is NULL, try to load the current executable instead.
 */
static int load_library(DrewLoader *ldr, const char *library,
		const char *path, library_t **libp)
{
	int err = 0;
	library_t *p, *lib;
	p = g_realloc(ldr->lib, sizeof(*p) * (ldr->nlibs + 1));
	if (!p)
		return -ENOMEM;
	if (p != ldr->lib) {
		// Fix up the lib pointers in the plugins.
		for (int i = 0; i < ldr->nplugins; i++)
			ldr->plugin[i].lib = p + (ldr->plugin[i].lib - ldr->lib);
	}
	ldr->lib = p;
	lib = &ldr->lib[ldr->nlibs];
	memset(lib, 0, sizeof(*lib));
	ldr->nlibs++;

	if (!library) {
		err = -DREW_ERR_RESOLUTION;
		if (!(lib->handle = open_library(NULL)))
			goto out;
		lib->name = g_strdup("<internal>");
		lib->path = NULL;
	}
	else {
		err = -ENOMEM;
		if (!(lib->path = g_strdup_printf("%s/%s", path, library)))
			goto out;
		// TODO: query this from the library.
		lib->name = g_strdup(library);
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
		g_free(lib->name);
		g_free(lib->path);
		lib->path = NULL;
		ldr->nlibs--;
	}
	return err;
}

/* Load all the info from the library, including all plugin-specific
 * information.
 */
static int load_library_info(DrewLoader *ldr, library_t *lib)
{
	int err = -DREW_ERR_ENUMERATION;
	int offset = ldr->nplugins;
	int extra = 0;
	plugin_t *p = NULL;

	lib->nplugins = lib->api(ldr, DREW_LOADER_GET_NPLUGINS, 0, NULL);
	if (lib->nplugins < 0)
		goto out;

	if (!lib->nplugins)
		extra = 1;

	err = -ENOMEM;
	p = g_realloc(ldr->plugin, sizeof(*p) * (ldr->nplugins + lib->nplugins + 1));
	if (!p)
		goto out;
	memset(p+ldr->nplugins, 0, sizeof(*p) * (lib->nplugins + 1));
	ldr->nplugins += lib->nplugins + extra;
	ldr->plugin = p;

	if (!lib->nplugins)
		p[ldr->nplugins-1].flags = FLAG_PLUGIN_DUMMY;

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
		p->functbl = g_malloc(p->functblsize);
		if (!p->functbl)
			goto out;

		if (mdsize) {
			p->metadata = g_malloc(mdsize);
			if (!p->metadata)
				goto out;
		}

		p->name = g_malloc(namesize);
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
		g_free(p->functbl);
		g_free(p->name);
		g_free(p->metadata);
	}
	return err ? err : offset;
}

DrewLoader *drew_loader_new(void)
{
	DrewLoader *ldr;

	if (!(ldr = g_slice_new(DrewLoader)))
		return NULL;

	memset(ldr, 0, sizeof(*ldr));

	ldr->ref_count = 1;

	// This protects everything except the reference count, which is atomic.
	g_rw_lock_init(&ldr->lock);

	return ldr;
}

DrewLoader *drew_loader_ref(DrewLoader *ldr)
{
	g_return_val_if_fail(ldr, NULL);
	
	g_atomic_int_inc(&ldr->ref_count);

	return ldr;
}

void drew_loader_unref(DrewLoader *ldr)
{
	g_return_if_fail(ldr);
	
	if (g_atomic_int_dec_and_test(&ldr->ref_count)) {
		g_rw_lock_clear(&ldr->lock);
		for (int i = 0; i < ldr->nlibs; i++) {
			g_free(ldr->lib[i].name);
			g_free(ldr->lib[i].path);
			close_library(ldr->lib[i].handle);
		}
		g_free(ldr->lib);
	
		for (int i = 0; i < ldr->nplugins; i++) {
			if (!(ldr->plugin[i].flags & FLAG_PLUGIN_OK))
				continue;
			g_free(ldr->plugin[i].name);
			g_free(ldr->plugin[i].functbl);
			g_free(ldr->plugin[i].metadata);
		}
		g_free(ldr->plugin);
		g_free(ldr);
	}

	return;
}

int drew_loader_load_plugin(DrewLoader *ldr, const char *plugin,
		const char *path)
{
	int retval = 0, err = 0;
	library_t *lib;

	g_rw_lock_writer_lock(&ldr->lock);

	if (plugin && !path) {
		int npaths = drew_loader_get_search_path(ldr, 0, NULL), i;

		if (npaths < 0) {
			retval = npaths;
			goto out;
		}

		for (i = 0; i < npaths; i++) {
			drew_loader_get_search_path(ldr, i, &path);
			if (!load_library(ldr, plugin, path, &lib))
				break;
		}
		if (i == npaths) {
			retval = -DREW_ERR_RESOLUTION;
			goto out;
		}
	}
	else if ((err = load_library(ldr, plugin, path, &lib))) {
		retval = err;
		goto out;
	}
	retval = load_library_info(ldr, lib);
out:
	g_rw_lock_writer_unlock(&ldr->lock);
	return retval;
}

static inline bool is_valid_id(DrewLoader *ldr, int id, int dummyok)
{
	int mask = FLAG_PLUGIN_OK | (dummyok ? FLAG_PLUGIN_DUMMY : 0);
	if (!ldr)
		return false;
	if (id < 0)
		return false;
	if (id >= ldr->nplugins)
		return false;
	if (!(ldr->plugin[id].flags & mask))
		return false;
	return true;
}

/* This function queries the number of plugins in the library which contains the
 * plugin with ID id.  As a special case, if id is -1, return the total number
 * of plugins loaded.
 */
int drew_loader_get_nplugins(DrewLoader *ldr, int id)
{
	int retval = 0;

	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	if (id == -1) {
		retval = ldr->nplugins;
		goto out;
	}
	if (!is_valid_id(ldr, id, 0)) {
		retval = is_valid_id(ldr, id, 1) ? 0 : -DREW_ERR_INVALID;
		goto out;
	}

	retval = ldr->plugin[id].lib->nplugins;
out:
	g_rw_lock_reader_unlock(&ldr->lock);
	return retval;
}

int drew_loader_get_type(DrewLoader *ldr, int id)
{
	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	int retval = is_valid_id(ldr, id, 0) ? ldr->plugin[id].type :
		-DREW_ERR_INVALID;

	g_rw_lock_reader_unlock(&ldr->lock);

	return retval;
}

int drew_loader_get_functbl(DrewLoader *ldr, int id, const void **tbl)
{
	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	int retval;

	if (!is_valid_id(ldr, id, 0)) {
		retval = -DREW_ERR_INVALID;
		goto out;
	}

	if (tbl)
		*tbl = ldr->plugin[id].functbl;

	retval = ldr->plugin[id].functblsize;

out:
	g_rw_lock_reader_unlock(&ldr->lock);
	return retval;
}

int drew_loader_get_algo_name(DrewLoader *ldr, int id,
		const char **namep)
{
	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	int retval = 0;

	if (!is_valid_id(ldr, id, 0))
		retval = -DREW_ERR_INVALID;
	else
		*namep = ldr->plugin[id].name;

	g_rw_lock_reader_unlock(&ldr->lock);

	return retval;
}

int drew_loader_lookup_by_name(DrewLoader *ldr, const char *name,
		int start, int end)
{
	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	if (end == -1)
		end = ldr->nplugins;

	for (int i = start; i < end; i++) {
		if (!is_valid_id(ldr, i, 0))
			continue;
		if (!strcmp(ldr->plugin[i].name, name)) {
			g_rw_lock_reader_unlock(&ldr->lock);
			return i;
		}
	}

	g_rw_lock_reader_unlock(&ldr->lock);

	return -DREW_ERR_NONEXISTENT;
}

int drew_loader_lookup_by_type(DrewLoader *ldr, int type, int start,
		int end)
{
	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	if (end == -1)
		end = ldr->nplugins;

	for (int i = start; i < end; i++) {
		if (!is_valid_id(ldr, i, 0))
			continue;
		if (ldr->plugin[i].type == type) {
			g_rw_lock_reader_unlock(&ldr->lock);
			return i;
		}
	}

	g_rw_lock_reader_unlock(&ldr->lock);

	return -DREW_ERR_NONEXISTENT;
}

/* This does not need to take the lock because it doesn't access ldr. */
int drew_loader_get_search_path(DrewLoader *ldr, int num,
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
static int special_metadata(DrewLoader *ldr, int id,
		int item, drew_metadata_t *meta)
{
	if (item > 0)
		return -DREW_ERR_NONEXISTENT;

	const char *path = ldr->plugin[id].lib->path;
	if (!path)
		return -DREW_ERR_NONEXISTENT;
	const char *prefix = "file://";
	struct stat st;
	const char *suffix = ".rdf";
	char *rdfpath = g_strjoin("", path, suffix, NULL);

	if (!stat(rdfpath, &st)) {
		if (meta) {
			char *obj;
			meta->version = 1;
			meta->subject = NULL;
			meta->predicate =
				g_strdup("http://www.w3.org/2000/01/rdf-schema#seeAlso");
			meta->type = DREW_LOADER_MD_URI;
			obj = g_strjoin("", prefix, rdfpath, NULL);
			meta->object = obj;
		}
		g_free(rdfpath);
		return 0;
	}
	g_free(rdfpath);
	return -DREW_ERR_NONEXISTENT;
}

int drew_loader_get_metadata(DrewLoader *ldr, int id, int item,
		drew_metadata_t *meta)
{
	drew_metadata_t md;
	int retval = 0;

	if (!ldr)
		return -DREW_ERR_INVALID;

	g_rw_lock_reader_lock(&ldr->lock);

	if (!is_valid_id(ldr, id, 0)) {
		g_rw_lock_reader_unlock(&ldr->lock);
		return -DREW_ERR_NONEXISTENT;
	}

	if (item == -1) {
		retval = special_metadata(ldr, id,
				(item - ldr->plugin[id].nmetadata), NULL);
		
		g_rw_lock_reader_unlock(&ldr->lock);
		return ldr->plugin[id].nmetadata + (retval == 0);
	}

	if (item < 0)
		return -DREW_ERR_INVALID;
	
	if (item < ldr->plugin[id].nmetadata) {
		memcpy(meta, ldr->plugin[id].metadata + item, sizeof(*meta));
		meta->predicate = g_strdup(meta->predicate);
		meta->object = g_strdup(meta->object);
		g_rw_lock_reader_unlock(&ldr->lock);
		return 0;
	}
	else {
		memset(&md, 0, sizeof(md));
		retval = special_metadata(ldr, id,
				(item - ldr->plugin[id].nmetadata), &md);
		if (retval < 0) {
			g_free((void *)md.predicate);
			g_free((void *)md.object);
			g_rw_lock_reader_unlock(&ldr->lock);
			return -DREW_ERR_NONEXISTENT;
		}
		memcpy(meta, &md, sizeof(*meta));
		g_rw_lock_reader_unlock(&ldr->lock);
		return 0;
	}

	g_rw_lock_reader_unlock(&ldr->lock);

	return -DREW_ERR_NONEXISTENT;
}

#include <version.h>
int drew_get_version(int op, const char **sp, void *p)
{
	if (op != 0)
		return -DREW_ERR_INVALID;
	if (p)
		return -DREW_ERR_INVALID;

	*sp = DREW_STRING_VERSION;
	return DREW_VERSION;
}


