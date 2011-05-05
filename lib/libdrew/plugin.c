#include "internal.h"
#include <drew/plugin.h>

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef int (*plugin_api_t)(void *, int, int, void *);

static int drew_loader__get_api(drew_loader_t *ldr, int aid,
		plugin_api_t *plugin_info)
{
	dlerror();
	*plugin_info = (plugin_api_t) dlsym(ldr->entry[aid].handle,
			"drew_plugin_info");
	if (dlerror() != NULL)
		return -DREW_ERR_RESOLUTION;
	return 0;
}

static int drew_loader__load_info(drew_loader_t *ldr, int aid, int id)
{
	plugin_api_t plugin_info;
	int type = 0;
	int nplugins = 0;
	int size = 0;
	int namesize = 0;
	int retval = 0;
	int metasize = 0;
	char *aname = 0;
	drew_metadata_t *metadata = 0;
	void *functbl = 0;

	if ((retval = drew_loader__get_api(ldr, aid, &plugin_info)))
		return retval;

	if (id == -1) {
		id = plugin_info(ldr, DREW_LOADER_LOOKUP_NAME, 0, ldr->entry[aid].name);
		if (id < 0)
			return -EINVAL;
	}

	nplugins = plugin_info(ldr, DREW_LOADER_GET_NPLUGINS, 0, NULL);
	if (!nplugins)
		goto done;
	if (nplugins < 0)
		return -DREW_ERR_ENUMERATION;

	if (id >= nplugins)
		return -EINVAL;

	type = plugin_info(ldr, DREW_LOADER_GET_TYPE, id, NULL);
	if (type < 0)
		return -DREW_ERR_ENUMERATION;

	size = plugin_info(ldr, DREW_LOADER_GET_FUNCTBL_SIZE, id, NULL);
	if (size < 0)
		return -DREW_ERR_ENUMERATION;
	
	functbl = malloc(size);
	if (!functbl)
		return -ENOMEM;

	if (plugin_info(ldr, DREW_LOADER_GET_FUNCTBL, id, functbl) < 0)
		return -DREW_ERR_FUNCTION;

	/* Includes terminating NUL. */
	namesize = plugin_info(ldr, DREW_LOADER_GET_NAME_SIZE, id, NULL);
	if (namesize < 0)
		return -DREW_ERR_ENUMERATION;

	aname = malloc(namesize);
	if (!aname)
		return -ENOMEM;

	if (plugin_info(ldr, DREW_LOADER_GET_NAME, id, aname) < 0)
		return -DREW_ERR_ENUMERATION;
	aname[namesize-1] = '\0'; /* Just in case. */

	metasize = plugin_info(ldr, DREW_LOADER_GET_METADATA_SIZE, id, 0);
	if ((metasize != -ENOENT) && (metasize != -EINVAL)) {
		if (metasize < 0)
			return -DREW_ERR_ENUMERATION;

		metadata = malloc(metasize);
		if (!metadata)
			return -ENOMEM;

		retval = plugin_info(ldr, DREW_LOADER_GET_METADATA, id, metadata);
		if (retval < 0)
			return -DREW_ERR_ENUMERATION;
	}
	else
		metasize = 0;

done:
	ldr->entry[aid].id = id;
	ldr->entry[aid].type = type;
	ldr->entry[aid].nplugins = nplugins;
	ldr->entry[aid].size = size;
	ldr->entry[aid].aname = aname;
	ldr->entry[aid].functbl = functbl;
	ldr->entry[aid].nmeta = metasize / sizeof(*metadata);
	ldr->entry[aid].metadata = metadata;

	return 0;
}

static bool drew_loader__is_valid_id(const drew_loader_t *ldr, int id)
{
	if (!ldr)
		return false;

	if (id < 0)
		return false;

	if (ldr->nentries <= id)
		return false;

	if (!ldr->entry[id].aname)
		return false;

	return true;
}

int drew_loader_new(drew_loader_t **ldr)
{
	drew_loader_t *p = NULL;

	if (!ldr)
		return -EINVAL;

	p = malloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	memset(p, 0, sizeof(*p));

	*ldr = p;
	return 0;
}

int drew_loader_free(drew_loader_t **ldr)
{
	if (!ldr)
		return -EINVAL;

	drew_loader_t *p = *ldr;

	if (!p)
		return 0;

	for (int i = 0; i < p->nentries; i++) {
		free(p->entry[i].name);
		free(p->entry[i].aname);
		free(p->entry[i].path);
		free(p->entry[i].metadata);
		free(p->entry[i].functbl);
		dlclose(p->entry[i].handle);
		memset(&p->entry[i], 0, sizeof(*p->entry));
	}
	free(p->entry);

	free(*ldr);
	*ldr = NULL;
	return 0;
}

static void *drew_loader__open_plugin(drew_loader_t *ldr, const char *plugin)
{
	return dlopen(plugin, RTLD_LAZY|RTLD_LOCAL);
}

static void drew_loader__close_handle(drew_loader_t *ldr, void *handle)
{
	dlclose(handle);
}

static int drew_loader__lookup_plugin(drew_loader_t *ldr, void **obj,
		const char *plugin, const char *path, char **fullpath)
{
	void *handle = NULL;
	int err = 0;
	char *dpath = NULL, *orig_dpath = NULL;
	const char *elem = NULL;

	*fullpath = NULL;

	if (!path) {
		handle = drew_loader__open_plugin(ldr, plugin);
		*fullpath = plugin ? realpath(plugin, NULL) : NULL;
		err = handle ? 0 : -ENOENT;
		goto out;
	}

	if (!(orig_dpath = dpath = strdup(path)))
		return -ENOMEM;

	for (; dpath && (elem = strsep(&dpath, ":")); ) {
		char *plugpath = NULL;
		int elemsz = strlen(elem), sz;
		int plugsz = strlen(plugin);

		if (!elemsz) {
			elem = ".";
			elemsz = 1;
		}

		err = -ENOMEM;
		sz = elemsz + 1 + plugsz + 1;
		plugpath = malloc(sz);
		if (!plugpath)
			goto out;
		if (snprintf(plugpath, sz, "%s/%s", elem, plugin) >= sz)
			goto out;

		if ((handle = drew_loader__open_plugin(ldr, plugpath))) {
			err = 0;
			*fullpath = realpath(plugpath, NULL);
			free(plugpath);
			goto out;
		}
	}
	err = -ENOENT;
out:
	free(orig_dpath);
	*obj = err ? NULL : handle;
	return err;
}

static int drew_loader__alloc_entry(drew_loader_t *ldr)
{
	drew_loader_entry_t *p;

	ldr->nentries++;
	p = realloc(ldr->entry, sizeof(*ldr->entry) * ldr->nentries);
	if (!p) {
		ldr->nentries--;
		return -ENOMEM;
	}
	ldr->entry = p;
	memset(&ldr->entry[ldr->nentries-1], 0, sizeof(*ldr->entry));
	return ldr->nentries - 1;
}

int drew_loader_load_plugin(drew_loader_t *ldr, const char *plugin,
		const char *path)
{
	void *handle = NULL;
	char *fullpath = NULL;
	int id = -1;
	int err = 0;
	int i;

	if ((err = drew_loader__lookup_plugin(ldr, &handle, plugin, path,
					&fullpath)))
		goto errout;

	if (!plugin) {
		plugin = "<internal>";
		fullpath = NULL;
	}

	err = -ENOENT;
	if (!handle)
		goto errout;

	err = -ENOMEM;
	id = drew_loader__alloc_entry(ldr);
	if (id < 0)
		goto errout;

	ldr->entry[id].handle = handle;
	ldr->entry[id].name = strdup(plugin);
	ldr->entry[id].path = fullpath;

	if ((err = drew_loader__load_info(ldr, id, 0)))
		goto errout;

	for (i = 1; i < ldr->entry[id].nplugins; i++) {
		int nid;

		err = -ENOMEM;
		nid = drew_loader__alloc_entry(ldr);
		if (nid < 0)
			goto errout;

		ldr->entry[nid].handle = handle;
		ldr->entry[nid].name = strdup(plugin);
		ldr->entry[nid].path = fullpath;
		if ((err = drew_loader__load_info(ldr, nid, i)))
			goto errout;
	}
	return id;
errout:
	if (id >= 0) {
		ldr->entry[id].handle = NULL;
		free(ldr->entry[id].name);
		ldr->entry[id].name = NULL;
	}
	free(fullpath);
	if (handle)
		drew_loader__close_handle(ldr, handle);
	return err;
}


int drew_loader_get_nplugins(const drew_loader_t *ldr, int id)
{
	if (!ldr)
		return -EINVAL;
	if (id == -1)
		return ldr->nentries;
	if (!drew_loader__is_valid_id(ldr, id))
		return -EINVAL;

	return ldr->entry[id].nplugins;
}

int drew_loader_get_type(const drew_loader_t *ldr, int id)
{
	if (!ldr || !drew_loader__is_valid_id(ldr, id))
		return -EINVAL;

	return ldr->entry[id].type;
}

int drew_loader_get_algo_name(const drew_loader_t *ldr, int id,
		const char **namep)
{
	if (!ldr || !drew_loader__is_valid_id(ldr, id))
		return -EINVAL;

	*namep = ldr->entry[id].aname;
	return 0;
}

int drew_loader_get_functbl(const drew_loader_t *ldr, int id, const void **tbl)
{
	if (!ldr || !drew_loader__is_valid_id(ldr, id))
		return -EINVAL;

	*tbl = ldr->entry[id].functbl;
	return ldr->entry[id].size;
}

int drew_loader_lookup_by_name(const drew_loader_t *ldr, const char *name,
		int start, int end)
{
	int i = 0;

	if (!ldr || !name)
		return -EINVAL;

	if (end == -1)
		end = ldr->nentries;

	if (end < start)
		return -EINVAL;

	for (i = start; i < end; i++) {
		if (!drew_loader__is_valid_id(ldr, i))
			continue;
		if (!strcmp(ldr->entry[i].aname, name))
			return i;
	}

	return -ENOENT;
}

int drew_loader_lookup_by_type(const drew_loader_t *ldr, int type, int start,
		int end)
{
	int i = 0;

	if (!ldr)
		return -EINVAL;

	if (end == -1)
		end = ldr->nentries;

	if (end < start)
		return -EINVAL;

	for (i = start; i < end; i++) {
		if (!drew_loader__is_valid_id(ldr, i))
			continue;
		if (ldr->entry[i].type == type)
			return i;
	}

	return -ENOENT;
}

/* This will eventually provide an rdf:seeAlso to an .rdf file with the same
 * basename as the plugin, and potentially provide some metadata that may
 * already be available, such as algorithm information and so forth.
 */
static int drew_loader__special_metadata(const drew_loader_t *ldr, int id,
		int item, drew_metadata_t *meta)
{
	if (item > 0)
		return -ENOENT;

	const char *path = ldr->entry[id].path;
	if (!path)
		return -ENOENT;
	const char *prefix = "file://";
	const size_t prefixlen = strlen(prefix);
	struct stat st;
	const char *suffix = ".rdf";
	const size_t suffixlen = strlen(suffix);
	size_t pathlen = strlen(path);
	char *rdfpath = malloc(pathlen + suffixlen + 1);

	strncpy(rdfpath, ldr->entry[id].path, pathlen);
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
	return -ENOENT;
}

int drew_loader_get_metadata(const drew_loader_t *ldr, int id, int item,
		drew_metadata_t *meta)
{
	drew_metadata_t md;
	int retval = 0;

	if (!ldr)
		return -EINVAL;

	if (!drew_loader__is_valid_id(ldr, id))
		return -ENOENT;

	if (item == -1) {
		retval = drew_loader__special_metadata(ldr, id,
				(item - ldr->entry[id].nmeta), NULL);
		
		return ldr->entry[id].nmeta + (retval == 0);
	}

	if (item < 0)
		return -EINVAL;
	
	if (item < ldr->entry[id].nmeta) {
		memcpy(meta, ldr->entry[id].metadata + item, sizeof(*meta));
		meta->predicate = strdup(meta->predicate);
		meta->object = strdup(meta->object);
		return 0;
	}
	else {
		memset(&md, 0, sizeof(md));
		retval = drew_loader__special_metadata(ldr, id,
				(item - ldr->entry[id].nmeta), &md);
		if (retval < 0) {
			free(md.predicate);
			free(md.object);
			return -ENOENT;
		}
		memcpy(meta, &md, sizeof(*meta));
		return 0;
	}

	return -ENOENT;
}
