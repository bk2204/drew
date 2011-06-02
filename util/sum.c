#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <drew/plugin.h>
#include <drew/hash.h>

#define MAX_DIGEST_BITS 512

#ifndef CHUNK_SIZE
#define CHUNK_SIZE 8192
#endif

#if CHUNK_SIZE % ALGO_BLOCK_SIZE
#error "CHUNK_SIZE is not a multiple of ALGO_BLOCK_SIZE!"
#endif

#if MAX_DIGEST_BITS > (8 * ALGO_DIGEST_SIZE)
#error "MAX_DIGEST_BITS is too small!"
#endif

#define MODE_TEXT 0
#define MODE_BINARY 1
#define MODE_CHECK 2

int initialize_hash(drew_hash_t *hash, const drew_loader_t *ldr, int id)
{
	const void *functbl;
	if (drew_loader_get_functbl(ldr, id, &functbl) < 0)
		return -1;
	hash->functbl = functbl;
	if (hash->functbl->init(hash, 0, NULL, NULL) < 0)
		return -1;
	return 0;
}

int process(uint8_t *val, const char *name, int mode, drew_hash_t *hash)
{
	FILE *fp = NULL;
	const char *modestr[] = {"r", "rb"};
	uint8_t buf[CHUNK_SIZE];
	size_t nread = 0;

	hash->functbl->reset(hash);

	if (!(fp = fopen(name, modestr[mode]))) {
		perror("error opening file");
		return -1;
	}

	while ((nread = fread(buf, 1, CHUNK_SIZE, fp)) == ALGO_BLOCK_SIZE)
		hash->functbl->updatefast(hash, buf, CHUNK_SIZE);

	if (nread < CHUNK_SIZE) {
		hash->functbl->update(hash, buf, nread);
		if (ferror(fp)) {
			perror("error reading file");
			fclose(fp);
			return -1;
		}
	}
	hash->functbl->final(hash, val, 0);

	fclose(fp);
	return 0;
}

void print(const uint8_t *buf, const char *name, int mode)
{
	for (int i = 0; i < ALGO_DIGEST_SIZE; i++)
		printf("%02x", buf[i]);
	printf(" %c%s\n", (mode == MODE_BINARY) ? '*' : ' ', name);
}

int main(int argc, char **argv)
{
	int c, mode = MODE_TEXT, id;
	int retval = 0;
	drew_loader_t *ldr;
	drew_hash_t hash;

	memset(&hash, 0, sizeof(hash));

	while ((c = getopt(argc, argv, "bct")) != -1) {
		switch (c) {
			case 'b':
				mode = MODE_BINARY;
				break;
			case 't':
				mode = MODE_TEXT;
				break;
			case 'c':
				mode = MODE_CHECK;
				break;
		}
	}

	drew_loader_new(&ldr);
	drew_loader_load_plugin(ldr, NULL, NULL);
	drew_loader_load_plugin(ldr, ALGO_PLUGIN_NAME, "./plugins");

	id = drew_loader_lookup_by_name(ldr, ALGO_NAME, 0, -1);
	if (id < 0) {
		retval = 3;
		goto out;
	}
	initialize_hash(&hash, ldr, id);

	if (mode == MODE_CHECK) {
		return 2;
	}
	else {
		const char *p;
		uint8_t val[MAX_DIGEST_BITS / 8];
		while ((p = argv[optind++])) {
			process(val, p, mode, &hash);
			print(val, p, mode);
		}
	}

out:
	if (hash.ctx)
		hash.functbl->fini(&hash, 0);
	drew_loader_free(&ldr);

	return retval;
}
