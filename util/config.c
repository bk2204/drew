#include <stddef.h>
#include <stdio.h>

#include <popt.h>

#include <drew/drew.h>
#include <drew/hash.h>

#define TYPE_DEFAULT 0
#define TYPE_VERSION 1
#define TYPE_PATHS 2
#define TYPE_MODULES 4

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

const struct poptOption options[] = {
	{ "version", 'v', 0, 0, TYPE_VERSION, "list version of libdrew" },
	{ "paths", 'p', 0, 0, TYPE_PATHS, "list library search paths" },
	{ "modules", 'm', 0, 0, TYPE_MODULES, "list modules" },
	POPT_AUTOHELP
	POPT_TABLEEND
};

const char *algo_types[] = {
	[0] = NULL,
	[DREW_TYPE_HASH] = "hash",
	[DREW_TYPE_BLOCK] = "block",
	[DREW_TYPE_MODE] = "mode",
	[DREW_TYPE_MAC] = "mac",
	[DREW_TYPE_STREAM] = "stream",
	[DREW_TYPE_PRNG] = "prng",
	[DREW_TYPE_BIGNUM] = "bignum",
	[DREW_TYPE_PKENC] = "pkenc",
	[DREW_TYPE_PKSIG] = "pksig",
	[DREW_TYPE_KDF] = "kdf",
	[DREW_TYPE_ECC] = "ecc",
};

int main(int argc, const char **argv)
{
	const char *p, *arg = NULL;
	int ver, c;
	int type = TYPE_DEFAULT;
	poptContext ctx;
	drew_loader_t *ldr;

	ctx = poptGetContext("drew-config", argc, argv, options, 0);

	while ((c = poptGetNextOpt(ctx)) >= 0)
		type |= c;

	ldr = drew_loader_new();
	drew_loader_load_plugin(ldr, NULL, NULL);
	while ((arg = poptGetArg(ctx)))
		drew_loader_load_plugin(ldr, arg, NULL);

	poptFreeContext(ctx);

	if (!type) {
		ver = drew_get_version(0, &p, NULL);
		printf("Drew version %d (%s)\n", ver, p);
	}
	if (type & TYPE_VERSION) {
		ver = drew_get_version(0, &p, NULL);
		printf("v0000: %d %s\n", ver, p);
	}
	if (type & TYPE_PATHS) {
		int npaths = drew_loader_get_search_path(ldr, 0, NULL);
		for (int i = 0; i < npaths; i++) {
			drew_loader_get_search_path(ldr, i, &p);
			printf("p%04x: %s\n", i, p);
		}
	}
	if (type & TYPE_MODULES) {
		int t = 0;
		for (int i = 0; (t = drew_loader_get_type(ldr, i)) >= 0; i++) {
			const char *at = NULL;
			// All we use this for is the info method (which is standard across
			// all types of plugins) to look up the ABI version.
			drew_hash_functbl_t *ft;

			drew_loader_get_algo_name(ldr, i, &p);
			if (t < DIM(algo_types))
				at = algo_types[t];
			drew_loader_get_functbl(ldr, i, (const void **)&ft);
			printf("m%04x: %s %d %s %d\n", i, p, t, at ? at : "?",
					ft->info(DREW_HASH_VERSION, NULL));
		}
	}
	drew_loader_unref(ldr);
	return 0;
}
