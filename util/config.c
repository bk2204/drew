#include <stddef.h>
#include <stdio.h>

#include <popt.h>

#include <drew/drew.h>

#define TYPE_DEFAULT 0
#define TYPE_VERSION 1
#define TYPE_PATHS 2

const struct poptOption options[] = {
	{ "version", 'v', 0, 0, TYPE_VERSION, "list version of libdrew" },
	{ "paths", 'p', 0, 0, TYPE_PATHS, "list library search paths" },
	POPT_AUTOHELP
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	const char *p;
	int ver, c;
	int type = TYPE_DEFAULT;
	poptContext ctx;
	drew_loader_t *ldr;

	ctx = poptGetContext("drew-config", argc, argv, options, 0);

	while ((c = poptGetNextOpt(ctx)) >= 0)
		type |= c;

	poptFreeContext(ctx);

	if (!type) {
		ver = drew_get_version(0, &p, NULL);
		printf("Drew version %d (%s)\n", ver, p);
		return 0;
	}
	if (type & TYPE_VERSION) {
		ver = drew_get_version(0, &p, NULL);
		printf("v0000: %d %s\n", ver, p);
	}
	drew_loader_new(&ldr);
	if (type & TYPE_PATHS) {
		int npaths = drew_loader_get_search_path(ldr, 0, NULL);
		for (int i = 0; i < npaths; i++) {
			drew_loader_get_search_path(ldr, i, &p);
			printf("p%04x: %s\n", i, p);
		}
	}
	drew_loader_free(&ldr);
	return 0;
}
