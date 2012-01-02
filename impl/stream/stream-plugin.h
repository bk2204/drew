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
#ifndef STREAM_PLUGIN_H
#define STREAM_PLUGIN_H

#ifndef DREW_IN_BUILD
#error "You really don't want to include this.  I promise."
#endif

#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <drew/plugin.h>
#include <drew/stream.h>

#define PLUGIN_FUNCTBL(prefix, info, info2, init, setiv, setkey, encrypt, decrypt, encryptfast, decryptfast, test, fini, clone, reset) \
\
static drew_stream_functbl_t prefix ## functbl = { \
	info, info2, init, clone, reset, fini, setiv, setkey, encrypt, decrypt, \
	encryptfast, decryptfast, test \
};

struct plugin {
	const char *name;
	drew_stream_functbl_t *functbl;
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
		return -DREW_ERR_INVALID; \
	switch (op) { \
		case DREW_LOADER_LOOKUP_NAME: \
			return 0; \
		case DREW_LOADER_GET_NPLUGINS: \
			return nplugins; \
		case DREW_LOADER_GET_TYPE: \
			return DREW_TYPE_STREAM; \
		case DREW_LOADER_GET_FUNCTBL_SIZE: \
			return sizeof(drew_stream_functbl_t); \
		case DREW_LOADER_GET_FUNCTBL: \
			memcpy(p, plugin_data[id].functbl, sizeof(drew_stream_functbl_t)); \
			return 0; \
		case DREW_LOADER_GET_NAME_SIZE: \
			return strlen(plugin_data[id].name) + 1; \
		case DREW_LOADER_GET_NAME: \
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1); \
			return 0; \
		default: \
			return -DREW_ERR_INVALID; \
	} \
} \
UNEXPORT()

#ifdef __cplusplus
}
#endif

#endif
