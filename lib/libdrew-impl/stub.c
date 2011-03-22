#include <internal.h>
#include <drew/plugin.h>

#include <stddef.h>
#include <errno.h>

#include "modules.gen"

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

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
