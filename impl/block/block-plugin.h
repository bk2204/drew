/*-
 * Copyright © 2010–2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#ifndef BLOCK_PLUGIN_H
#define BLOCK_PLUGIN_H

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <drew/plugin.h>
#include <drew/block.h>

#ifndef DEPEND
#include "metadata.gen"
#endif

#define PLUGIN_FUNCTBL(prefix, info, info2, init, setkey, encrypt, decrypt, encryptmult, decryptmult, test, fini, clone, reset) \
\
static const drew_block_functbl_t prefix ## functbl = { \
	info, info2, init, clone, reset, fini, setkey, encrypt, decrypt, \
	encryptmult, decryptmult, test \
};

struct plugin {
	const char *name;
	const drew_block_functbl_t *functbl;
};

#define PLUGIN_DATA_START() static struct plugin plugin_data[] = {
#define PLUGIN_DATA_END() };
#define PLUGIN_DATA(prefix, name) { name, & prefix ## functbl },

#define PLUGIN_INFO(name) static const char *pname = name
#ifdef DREW_PLUGIN_METADATA_NONEMPTY
#define PLUGIN_INTERFACE_METADATA(x) \
		case DREW_LOADER_GET_METADATA_SIZE: \
			return sizeof(x ## _metadata); \
		case DREW_LOADER_GET_METADATA: \
			memcpy(p, x ## _metadata, sizeof(x ## _metadata)); \
			return 0;
#else
#define PLUGIN_INTERFACE_METADATA(x)
#endif
#define PLUGIN_INTERFACE(x) \
\
EXPORT() \
int DREW_PLUGIN_NAME(x)(void *ldr, int op, int id, void *p) \
{ \
\
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]); \
	if (id < 0 || id >= nplugins) \
		return -DREW_ERR_INVALID; \
	switch (op) { \
		case DREW_LOADER_LOOKUP_NAME: \
			return 0; \
		case DREW_LOADER_GET_NPLUGINS: \
			return nplugins; \
		case DREW_LOADER_GET_TYPE: \
			return DREW_TYPE_BLOCK; \
		case DREW_LOADER_GET_FUNCTBL_SIZE: \
			return sizeof(drew_block_functbl_t); \
		case DREW_LOADER_GET_FUNCTBL: \
			memcpy(p, plugin_data[id].functbl, sizeof(drew_block_functbl_t)); \
			return 0; \
		case DREW_LOADER_GET_NAME_SIZE: \
			return strlen(plugin_data[id].name) + 1; \
		case DREW_LOADER_GET_NAME: \
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1); \
			return 0; \
		PLUGIN_INTERFACE_METADATA(x) \
		default: \
			return -DREW_ERR_INVALID; \
	} \
} \
UNEXPORT()

#ifdef __cplusplus
}
#endif

#endif
