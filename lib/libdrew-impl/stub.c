/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#include <internal.h>
#include <drew/plugin.h>

#include <stddef.h>
#include <errno.h>

#include "modules.gen"

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

DREW_SYM_PUBLIC
int drew_plugin_info(void *ldr, int op, int id, void *p)
{
	int plugcnt = 0;
	for (size_t i = 0; i < DIM(plugin_list); i++) {
		int nplugins = plugin_list[i](ldr, DREW_LOADER_GET_NPLUGINS, 0, NULL);
		if ((op != DREW_LOADER_GET_NPLUGINS) && (id < (nplugins + plugcnt))) {
			return plugin_list[i](ldr, op, id-plugcnt, p);
		}
		else
			plugcnt += nplugins;
	}
	if (op == DREW_LOADER_GET_NPLUGINS)
		return plugcnt;
	return -EINVAL;
}
