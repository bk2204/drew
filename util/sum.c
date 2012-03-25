/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
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

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MODE_TEXT 0
#define MODE_BINARY 1
#define MODE_CHECK 2

static const char *program = NULL;

struct algomap {
	const char *command;
	const char *algo;
	drew_hash_t hash;
	size_t digest_size;
	size_t block_size;
};

static struct algomap thisalgo;

int initialize_hash(const drew_loader_t *ldr, int id)
{
	const void *functbl;
	int res = 0;
	drew_hash_t *hash = &thisalgo.hash;

	memset(hash, 0, sizeof(*hash));

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

	if ((res = hash->functbl->info2(hash, DREW_HASH_SIZE_CTX, NULL, NULL))
			< 0) {
		fprintf(stderr, "%s: error finding digest size: error %d\n", program,
				-res);
		return -1;
	}
	thisalgo.digest_size = res;

	if ((res = hash->functbl->info2(hash, DREW_HASH_BLKSIZE_CTX, NULL, NULL))
			< 0) {
		fprintf(stderr, "%s: error finding block size: error %d\n", program,
				-res);
		return -1;
	}
	thisalgo.block_size = res;

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
	hash->functbl->final(hash, val, thisalgo.digest_size, 0);

	fclose(fp);
	return 0;
}

void print(const uint8_t *buf, const char *name, int mode)
{
	for (int i = 0; i < thisalgo.digest_size; i++)
		printf("%02x", buf[i]);
	printf(" %c%s\n", (mode == MODE_BINARY) ? '*' : ' ', name ? name : "-");
}

int check(const char *filename, drew_hash_t *hash)
{
	int errors = 0;
	FILE *fp;
	char buf[(MAX_DIGEST_BITS / 8 * 2) + 2 + PATH_MAX + 2];

	if (!filename) 
		fp = stdin;
	else if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "%s: error opening file %s with mode %s: %s\n", program,
				filename, "r", strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		uint8_t val[MAX_DIGEST_BITS / 8], computed[MAX_DIGEST_BITS / 8];
		size_t len = strlen(buf);
		char *filename;
		char dummy, type;
		int mode, cmp;
		if (buf[len-1] != '\n')
			continue;
		buf[len-1] = '\0';
		for (int i = 0; i < thisalgo.digest_size; i++)
			if (!sscanf(buf+(2*i), "%02hhx", val+i))
				goto next;
		if (sscanf(buf+(2*thisalgo.digest_size), "%c%c%ms", &dummy, &type,
					&filename) != 3)
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

int usage(int ret)
{
	printf("Usage: %s [-tbc] [file]...\nPrint or check %s hashes.\n", program,
			thisalgo.algo);
	return ret;
}

int gnusum_main(int argc, char **argv, const drew_loader_t *ldr, int id)
{
	int c, mode = MODE_TEXT;
	int retval = 0;
	drew_hash_t *hash = &thisalgo.hash;

	while ((c = getopt(argc, argv, "bct-:")) != -1) {
		if (c == '-') {
			if (!strcmp(optarg, "text"))
				c = 't';
			else if (!strcmp(optarg, "binary"))
				c = 'b';
			else if (!strcmp(optarg, "check"))
				c = 'c';
			else if (!strcmp(optarg, "help"))
				return usage(0);
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
			case '?':
				return usage(2);
		}
	}

	if (mode == MODE_CHECK) {
		const char *p = argv[optind];
		do {
			if (check(p, hash))
				retval = 1;
		}
		while (p && (p = argv[++optind]));
	}
	else {
		uint8_t val[MAX_DIGEST_BITS / 8];
		const char *p = argv[optind];
		do {
			if (process(val, p, mode, hash))
				retval = 1;
			print(val, p, mode);
		}
		while (p && (p = argv[++optind]));
	}

	if (hash->ctx)
		hash->functbl->fini(hash, 0);

	return retval;
}

// Returns an id for the loader and fills in thisalgo on success; returns -1 on
// failure.
int convert_name_to_algo(const char *name, const char *suffix,
		drew_loader_t *ldr)
{
	int id = -1;
	char *s, *olds, *p, *variant, *oldv = NULL;
	size_t len, slen;

	olds = s = strdup(name);
	len = strlen(name);
	slen = suffix ? strlen(suffix) : 0;

	// Strip a suffix.
	if (!strcmp(suffix, s+len-slen)) {
		s[len-slen] = '\0';
	}
	// Strip a pathname.
	if ((p = strrchr(s, '/')))
		s = p + 1;
	// Strip a prefix.
	if (!strncmp(s, "drew-", 5))
		s += 5;

	thisalgo.command = s;

	len = strlen(s);

	// Load a plugin if one exists.
	drew_loader_load_plugin(ldr, s, NULL);

	// Try the lowercase name (unlikely).
	thisalgo.algo = s;
	id = drew_loader_lookup_by_name(ldr, s, 0, -1);
	if (id >= 0)
		goto out;

	bool mark = false;
	char prev = 0;
	oldv = variant = malloc(len + 2);
	for (p = s; *p; prev = *p, variant++, p++) {
		if (!mark && isalpha(prev) && isdigit(*p)) {
			mark = true;
			*variant++ = '-';
		}
		*variant = *p;
	}
	*variant = '\0';
	variant = oldv;

	// Try with a dash in between the letters and numbers.
	thisalgo.algo = variant;
	id = drew_loader_lookup_by_name(ldr, variant, 0, -1);
	if (id >= 0 && drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
		goto out;

	*s = toupper(*s);
	*variant = toupper(*variant);

	// Try in title case.
	thisalgo.algo = s;
	id = drew_loader_lookup_by_name(ldr, s, 0, -1);
	if (id >= 0 && drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
		goto out;

	thisalgo.algo = variant;
	id = drew_loader_lookup_by_name(ldr, variant, 0, -1);
	if (id >= 0 && drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
		goto out;

	for (p = s; *p; p++, variant++) {
		*p = toupper(*p);
		*variant = toupper(*variant);
	}
	variant = oldv;

	// Try in upper case.
	thisalgo.algo = s;
	id = drew_loader_lookup_by_name(ldr, s, 0, -1);
	if (id >= 0 && drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
		goto out;

	thisalgo.algo = variant;
	id = drew_loader_lookup_by_name(ldr, variant, 0, -1);
	if (id >= 0 && drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
		goto out;

	// Okay, we give up.
out:
	if (id >= 0) {
		int ret = initialize_hash(ldr, id);
		if (ret < 0)
			id = ret;
	}
	free(olds);
	free(oldv);
	return id;
}

int main(int argc, char **argv)
{
	drew_loader_t *ldr;
	int ret = 2, id = -1;

	program = argv[0];

	drew_loader_new(&ldr);
	drew_loader_load_plugin(ldr, NULL, NULL);

	if (!strcmp("sum", program+strlen(program)-3) &&
			(id = convert_name_to_algo(program, "sum", ldr) >= 0))
		ret = gnusum_main(argc, argv, ldr, id);
	else if (!strcmp("drew-sum", program+strlen(program)-8) &&
			(id = convert_name_to_algo("drew-sha512sum", "sum", ldr) >= 0))
		ret = gnusum_main(argc, argv, ldr, id);
	else {
		fprintf(stderr, "%s: I don't understand what you want me to do\n",
				program);
		ret = 2;
	}

	drew_loader_free(&ldr);

	return ret;
}
