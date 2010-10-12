#include "plugin.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void errprint(int val, int retval)
{
	val = -val;
	fprintf(stderr, "Error %d (%s) at stage %d\n", val, strerror(val), retval);
	exit(retval);
}

int main(int argc, char **argv)
{
	drew_loader_t *ldr = NULL;
	int size = 0;
	int id = 0;
	int type = 0, nplugins = 0;
	const void *tbl = NULL;

	if (argc < 2)
		return 2;

	if (drew_loader_new(&ldr))
		return 3;
	if ((id = drew_loader_load_plugin(ldr, argv[1], NULL)) < 0)
		errprint(id, 4);
	if ((size = drew_loader_get_functbl(ldr, id, &tbl)) < 0)
		return 5;
	if ((nplugins = drew_loader_get_nplugins(ldr, id)) < 0)
		return 6;
	if ((type = drew_loader_get_type(ldr, id)) < 0)
		return 7;
	if (drew_loader_free(&ldr))
		return 125;

	printf("Loaded plugin %s (id %d of %d).\n", argv[1], id, nplugins);
	printf("  Plugin type is %#x.\n", type);
	printf("  Function table is at %p (%d bytes).\n", tbl, size);

	return 0;
}
