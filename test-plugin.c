/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#include "plugin.h"

#include <drew/drew.h>

static int func(void)
{
	return 0;
}

static void *functbl[] = {
	&func
};

int drew_plugin_info(void *ldr, int op, int id, void *p)
{
	void **tbl = p;

	switch (op) {
		case DREW_LOADER_LOOKUP_NAME:
			return 0;
		case DREW_LOADER_GET_NPLUGINS:
			return 1;
		case DREW_LOADER_GET_TYPE:
			return 1;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(functbl);
		case DREW_LOADER_GET_FUNCTBL:
			*tbl = functbl;
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}
