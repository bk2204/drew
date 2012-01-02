/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#include <errno.h>
#include <limits.h>
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

#if MAX_DIGEST_BITS < (8 * ALGO_DIGEST_SIZE)
#error "MAX_DIGEST_BITS is too small!"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MODE_TEXT 0
#define MODE_BINARY 1
#define MODE_CHECK 2

static const char *program = NULL;

int initialize_hash(drew_hash_t *hash, const drew_loader_t *ldr, int id)
{
	const void *functbl;
	int res = 0;
	if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0) {
		fprintf(stderr, "%s: error loading interface: error %d\n", program,
				-res);
		return -1;
	}
	hash->functbl = functbl;
	if ((res = hash->functbl->init(hash, 0, NULL, NULL)) < 0) {
		fprintf(stderr, "%s: error initializing algorithm: error %d\n", program,
				-res);
		return -1;
	}
	return 0;
}

int process(uint8_t *val, const char *name, int mode, drew_hash_t *hash)
{
	FILE *fp = NULL;
	const char *modestr[] = {"r", "rb"};
	uint8_t buf[CHUNK_SIZE];
	size_t nread = 0;

	hash->functbl->reset(hash);

	if (!name)
		fp = stdin;
	else if (!(fp = fopen(name, modestr[mode]))) {
		fprintf(stderr, "%s: error opening file %s with mode %s: %s\n", program,
				name, modestr[mode], strerror(errno));
		return -1;
	}

	while ((nread = fread(buf, 1, CHUNK_SIZE, fp)) == CHUNK_SIZE)
		hash->functbl->updatefast(hash, buf, CHUNK_SIZE);

	if (nread < CHUNK_SIZE) {
		hash->functbl->update(hash, buf, nread);
		if (ferror(fp)) {
			fprintf(stderr, "%s: error reading file %s: %s\n", program, name,
					strerror(errno));
			fclose(fp);
			return -1;
		}
	}
	hash->functbl->final(hash, val, ALGO_DIGEST_SIZE, 0);

	fclose(fp);
	return 0;
}

void print(const uint8_t *buf, const char *name, int mode)
{
	for (int i = 0; i < ALGO_DIGEST_SIZE; i++)
		printf("%02x", buf[i]);
	printf(" %c%s\n", (mode == MODE_BINARY) ? '*' : ' ', name ? name : "-");
}

int check(const char *filename, drew_hash_t *hash)
{
	int errors = 0;
	FILE *fp;
	char buf[(ALGO_DIGEST_SIZE * 2) + 2 + PATH_MAX + 2];

	if (!filename) 
		fp = stdin;
	else if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "%s: error opening file %s with mode %s: %s\n", program,
				filename, "r", strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		uint8_t val[ALGO_DIGEST_SIZE], computed[ALGO_DIGEST_SIZE];
		size_t len = strlen(buf);
		char *filename;
		char dummy, type;
		int mode, cmp;
		if (buf[len-1] != '\n')
			continue;
		buf[len-1] = '\0';
		for (int i = 0; i < ALGO_DIGEST_SIZE; i++)
			if (!sscanf(buf+(2*i), "%02hhx", val+i))
				goto next;
		if (sscanf(buf+(2*ALGO_DIGEST_SIZE), "%c%c%ms", &dummy, &type, &filename) != 3)
			continue;
		if (dummy != ' ')
			continue;
		switch (type) {
			case ' ':
				mode = MODE_TEXT;
				break;
			case '*':
				mode = MODE_BINARY;
				break;
			default:
				continue;
		}
		if (process(computed, filename, mode, hash) < 0)
			continue;
		if ((cmp = memcmp(computed, val, sizeof(val))))
			errors++;
		printf("%s: %s\n", filename, cmp ?  "FAILED" : "OK");
next:
		;
	}

	fclose(fp);
	return errors;
}

int main(int argc, char **argv)
{
	int c, mode = MODE_TEXT, id;
	int retval = 0;
	drew_loader_t *ldr;
	drew_hash_t hash;

	program = argv[0];

	memset(&hash, 0, sizeof(hash));

	while ((c = getopt(argc, argv, "bct-:")) != -1) {
		if (c == '-') {
			if (!strcmp(optarg, "text"))
				c = 't';
			else if (!strcmp(optarg, "binary"))
				c = 'b';
			else if (!strcmp(optarg, "check"))
				c = 'c';
			else
				c = '?';
		}
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
	drew_loader_load_plugin(ldr, ALGO_PLUGIN_NAME, NULL);
	drew_loader_load_plugin(ldr, ALGO_PLUGIN_NAME, "./plugins");

	id = drew_loader_lookup_by_name(ldr, ALGO_NAME, 0, -1);
	if (id < 0) {
		fprintf(stderr, "%s: error looking up algorithm: error %d\n", program,
				id);
		retval = 3;
		goto out;
	}
	if (initialize_hash(&hash, ldr, id)) {
		retval = 4;
		goto out;
	}

	if (mode == MODE_CHECK) {
		const char *p = argv[optind];
		do {
			if (check(p, &hash))
				retval = 1;
		}
		while (p && (p = argv[++optind]));
	}
	else {
		uint8_t val[MAX_DIGEST_BITS / 8];
		const char *p = argv[optind];
		do {
			if (process(val, p, mode, &hash))
				retval = 1;
			print(val, p, mode);
		}
		while (p && (p = argv[++optind]));
	}

out:
	if (hash.ctx)
		hash.functbl->fini(&hash, 0);
	drew_loader_free(&ldr);

	return retval;
}
