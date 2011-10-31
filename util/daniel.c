/*-
 * Copyright © 2011 brian m. carlson
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <drew/block.h>
#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/kdf.h>
#include <drew/mem.h>
#include <drew/mode.h>
#include <drew/plugin.h>

typedef uint8_t buffer_t[32];

static const char *program = NULL;
static const char *prefix = "DrewPassChart: Version 0x00000000: ";

#define FLAG_NO_NUMBERS			0x01
#define FLAG_NO_SPACES			0x02
#define FLAG_NO_SYMBOLS_TOP		0x04
#define FLAG_NO_SYMBOLS_OTHER	0x08
#define FLAG_NO_LETTERS 		0x10
/* This is the version of the DrewPassChart generator (see prefix), not the
 * version of the password generated.
 */
#define FLAG_EXPLICIT_VERSION	0x40

struct crypto {
	drew_loader_t *ldr;
	drew_kdf_t *kdf;
	drew_kdf_t *prf;
	drew_hash_t *hash;
	drew_mode_t *mode;
	drew_block_t *block;
};

struct generic {
	void *ctx;
	const void *functbl;
	void *priv;
};

struct data {
	char qc[6 + 1];
	uint8_t master_secret[32];
	int flags;
	int version;
	int length;
};

int initialize_ctx(void *c, const drew_loader_t *ldr, const char *name)
{
	struct generic *ctx = c;
	int res = 0, id = 0;

	id = drew_loader_lookup_by_name(ldr, name, 0, -1);
	if (id < 0) {
		fprintf(stderr, "%s: can't find %s: error %d\n", program, name, -id);
		return 3;
	}
	if ((res = drew_loader_get_functbl(ldr, id, &ctx->functbl)) < 0) {
		fprintf(stderr, "%s: can't load %s interface: error %d\n", program,
				name, -res);
		return 4;
	}
	return 0;
}

int set_up_crypto(struct crypto *c)
{
	drew_loader_t *ldr;
	int res = 0, ctxno = 0;
	drew_kdf_t *kdf = drew_mem_malloc(sizeof(*kdf));
	drew_kdf_t *prf = drew_mem_malloc(sizeof(*kdf));
	drew_hash_t *hash = drew_mem_malloc(sizeof(*hash));
	drew_mode_t *mode = drew_mem_malloc(sizeof(*mode));
	drew_block_t *block = drew_mem_malloc(sizeof(*block));
	drew_param_t param;

	drew_loader_new(&ldr);
	drew_loader_load_plugin(ldr, NULL, NULL);
	drew_loader_load_plugin(ldr, "sha256", NULL);
	drew_loader_load_plugin(ldr, "aesni", NULL);
	drew_loader_load_plugin(ldr, "aes", NULL);
	drew_loader_load_plugin(ldr, "rijndael", NULL);
	drew_loader_load_plugin(ldr, "ctr", NULL);
	drew_loader_load_plugin(ldr, "pbkdf2", NULL);
	drew_loader_load_plugin(ldr, "hmac", NULL);

	c->ldr = ldr;

	if ((res = initialize_ctx(hash, ldr, "SHA-256")))
		return res;
	if ((res = hash->functbl->init(hash, 0, ldr, NULL)))
		goto err;
	c->hash = hash;
	ctxno++;

	if ((res = initialize_ctx(block, ldr, "AES256")))
		return res;
	if ((res = block->functbl->init(block, 0, ldr, NULL)))
		goto err;
	c->block = block;
	ctxno++;

	if ((res = initialize_ctx(mode, ldr, "CTR")))
		return res;
	if ((res = mode->functbl->init(mode, 0, ldr, NULL)))
		goto err;
	c->mode = mode;
	ctxno++;

	if ((res = initialize_ctx(prf, ldr, "HMAC-KDF")))
		return res;
	param.next = NULL;
	param.name = "digest";
	param.param.value = hash;
	if ((res = prf->functbl->init(prf, 0, ldr, &param)))
		goto err;
	c->prf = prf;
	ctxno++;

	if ((res = initialize_ctx(kdf, ldr, "PBKDF2")))
		return res;
	param.next = NULL;
	param.name = "prf";
	param.param.value = prf;
	if ((res = kdf->functbl->init(kdf, 0, ldr, &param)))
		goto err;
	c->kdf = kdf;
	ctxno++;

	return 0;
err:
	fprintf(stderr, "%s: failed initializing context %d: %05x\n", program,
			ctxno, -res);
	return 5;
}

void free_crypto(struct crypto *c)
{
	c->kdf->functbl->fini(c->kdf, 0);
	c->prf->functbl->fini(c->prf, 0);
	c->mode->functbl->fini(c->mode, 0);
	c->block->functbl->fini(c->block, 0);
	c->hash->functbl->fini(c->hash, 0);

	drew_mem_free(c->kdf);
	drew_mem_free(c->prf);
	drew_mem_free(c->mode);
	drew_mem_free(c->block);
	drew_mem_free(c->hash);
	drew_loader_free(&c->ldr);
}

inline void store_uint32(uint8_t *p, uint32_t x)
{
	p[0] = (uint8_t)(x >> 24);
	p[1] = (uint8_t)(x >> 16);
	p[2] = (uint8_t)(x >> 8);
	p[3] = (uint8_t)(x);
}

void process_strings(struct crypto *c, uint8_t *out, size_t nbytes,
		const char **strs, size_t nstrs, const uint8_t *data, size_t len)
{
	// TODO: validate strings as UTF-8.
	size_t tsize = 0, off = 0;
	uint8_t *buf;
	for (size_t i = 0; i < nstrs; tsize += strlen(strs[i]) + 4, i++);
	buf = drew_mem_smalloc(tsize);
	for (size_t i = 0; i < nstrs; i++) {
		size_t sl = strlen(strs[i]);
		store_uint32(buf+off, sl);
		off += 4;
		memcpy(buf+off, strs[i], sl);
		off += sl;
	}
	c->kdf->functbl->reset(c->kdf);
	c->kdf->functbl->setsalt(c->kdf, data, len);
	c->kdf->functbl->setcount(c->kdf, 1024);
	c->kdf->functbl->generate(c->kdf, out, nbytes, buf, tsize);
	drew_mem_sfree(buf);
}

void process_strings_fast(struct crypto *c, uint8_t *out, size_t nbytes,
		const char **strs, size_t nstrs, const uint8_t *data, size_t len)
{
	size_t tsize = 0, off = 0;
	uint8_t *buf, tmp[sizeof(uint32_t)], output[32];
	drew_hash_t hash;
	for (size_t i = 0; i < nstrs; tsize += strlen(strs[i]) + 4, i++);
	buf = drew_mem_smalloc(tsize);
	for (size_t i = 0; i < nstrs; i++) {
		size_t sl = strlen(strs[i]);
		store_uint32(buf+off, sl);
		off += 4;
		memcpy(buf+off, strs[i], sl);
		off += sl;
	}
	c->hash->functbl->clone(&hash, c->hash, 0);
	hash.functbl->reset(&hash);
	hash.functbl->update(&hash, buf, tsize);
	store_uint32(tmp, len);
	hash.functbl->update(&hash, tmp, 4);
	hash.functbl->update(&hash, data, len);
	hash.functbl->final(&hash, output, sizeof(output), 0);
	memcpy(out, output, nbytes);
	hash.functbl->fini(&hash, 0);
	drew_mem_sfree(buf);
}

void calculate_quick_check(struct crypto *c, struct data *d)
{
	uint8_t buf[3];
	const char *strs[2];
	strs[0] = prefix;
	strs[1] = "Quick Check: ";
	process_strings_fast(c, buf, sizeof(buf), strs, 2, d->master_secret,
			sizeof(d->master_secret));
	snprintf(d->qc, sizeof(d->qc), "%02x%02x%02x", buf[0], buf[1], buf[2]);
}

#define BUFFER_SIZE 512
int get_master_secret(struct crypto *c, struct data *d)
{
	int fd = 0, retval = 0;
	char *buf, *res = NULL;
	ssize_t nread = 0;
	struct termios tios, old;
	buf = drew_mem_smalloc(BUFFER_SIZE);
	if (isatty(fd)) {
		if (tcgetattr(fd, &tios)) {
			fprintf(stderr, "%s: can't get echo setting: %d\n", program, errno);
			return 10;
		}
		memcpy(&old, &tios, sizeof(tios));
		printf("Please enter your master password: ");
		fflush(stdout);
		tios.c_lflag &= ~ECHO;
		tios.c_lflag |= ECHONL;
		if (tcsetattr(fd, TCSAFLUSH, &tios)) {
			fprintf(stderr, "%s: can't turn off echo: %d\n", program, errno);
			return 10;
		}
		if (tcgetattr(fd, &tios) || (tios.c_lflag & (ECHO|ECHONL)) != ECHONL) {
			fprintf(stderr, "%s: can't turn off echo: %d\n", program, errno);
			return 10;
		}
	}
	res = fgets(buf, BUFFER_SIZE, stdin);
	if (isatty(fd)) {
		if (tcsetattr(fd, TCSAFLUSH, &old)) {
			fprintf(stderr, "%s: can't turn on echo: %d\n", program, errno);
			retval = 10;
		}
	}
	if (!res) {
		fprintf(stderr, "%s: error reading master secret: %d\n", program,
				errno);
		retval = 11;
	}
	if (!retval) {
		const char *strs[3];
		nread = strlen(buf);
		if (buf[nread-1] == '\n')
			buf[nread-1] = '\0';
		strs[0] = prefix;
		strs[1] = "Master Secret: ";
		strs[2] = buf;
		process_strings(c, d->master_secret, sizeof(d->master_secret), strs, 3,
				NULL, 0);
	}
	drew_mem_sfree(buf);
	return retval;
}

int get_code(char *buf, size_t buflen)
{
	size_t nread;
	if (isatty(0))
		printf("Enter code: ");
	if (!fgets(buf, buflen, stdin))
		return 1;
	nread = strlen(buf);
	if (buf[nread-1] == '\n')
		buf[nread-1] = '\0';
	return 0;
}

#define FL(x) (FLAG_NO_ ## x)
static const int charclass[] = {
	/* 0x00 */
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	/* 0x10 */
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	/* 0x20 */
	FL(SPACES), FL(SYMBOLS_TOP), FL(SYMBOLS_OTHER), FL(SYMBOLS_TOP),
	FL(SYMBOLS_TOP), FL(SYMBOLS_TOP), FL(SYMBOLS_TOP), FL(SYMBOLS_OTHER),
	FL(SYMBOLS_TOP), FL(SYMBOLS_TOP), FL(SYMBOLS_TOP), FL(SYMBOLS_OTHER),
	FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER),
	/* 0x30 */
	FL(NUMBERS), FL(NUMBERS), FL(NUMBERS), FL(NUMBERS),
	FL(NUMBERS), FL(NUMBERS), FL(NUMBERS), FL(NUMBERS),
	FL(NUMBERS), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER),
	FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER),
	/* 0x40 */
	FL(SYMBOLS_TOP), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	/* 0x50 */
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(SYMBOLS_OTHER),
	FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_TOP), FL(SYMBOLS_OTHER),
	/* 0x60 */
	FL(SYMBOLS_OTHER), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	/* 0x70 */
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(LETTERS),
	FL(LETTERS), FL(LETTERS), FL(LETTERS), FL(SYMBOLS_OTHER),
	FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), FL(SYMBOLS_OTHER), -1
};

#define IVLEN 16
void generate_password(struct crypto *c, struct data *d, const char *s,
		int flags, int version, int size, int reminder)
{
	const uint8_t zero[IVLEN] = {0x00};
	const char *strs[5];
	char flagsb[BUFFER_SIZE], versionb[BUFFER_SIZE];
	uint8_t *iv = drew_mem_smalloc(IVLEN);
	uint8_t *buf = drew_mem_smalloc(IVLEN);

	snprintf(flagsb, sizeof(flagsb), "Flags 0x%08x: ", flags);
	snprintf(versionb, sizeof(versionb), "Version 0x%08x: ", version);
	strs[0] = prefix;
	strs[1] = "IV: ";
	strs[2] = flagsb;
	strs[3] = versionb;
	strs[4] = s;
	process_strings(c, iv, IVLEN, strs, 5, d->master_secret,
			sizeof(d->master_secret));

	c->block->functbl->reset(c->block);
	c->block->functbl->setkey(c->block, d->master_secret,
			sizeof(d->master_secret), DREW_BLOCK_MODE_ENCRYPT);
	c->mode->functbl->reset(c->mode);
	c->mode->functbl->setblock(c->mode, c->block);
	c->mode->functbl->setiv(c->mode, iv, IVLEN);

	printf("Password is: ");

	for (int off = 0; off < size; ) {
		c->mode->functbl->encrypt(c->mode, buf, zero, IVLEN);
		for (int i = 0; i < IVLEN && off < size; i++) {
			int class;
			if (buf[i] >= 0x80)
				continue;
			class = charclass[buf[i]];
			if (class != -1 && (flags & class) == 0) {
				off++;
				putchar(buf[i]);
			}
		}
	}
	putchar('\n');
	if (reminder) {
		printf("Reminder is: ");
		if (flags & FLAG_EXPLICIT_VERSION)
			printf("%s%02x%02x%02x%02x%s\n", d->qc, flags, 0, size, version, s);
		else
			printf("%s%02x%02x%02x%s\n", d->qc, flags, size, version, s);
	}

	drew_mem_sfree(iv);
	drew_mem_sfree(buf);
}

int generate_password_from_reminder(struct crypto *c, struct data *d,
		const char *s)
{
	char qcbuf[6 + 1], *t;
	int flags, size, version, off = 8, format = 0;
	if (sscanf(s, "%6s%02x", qcbuf, &flags) != 2 || (flags & 0x80)) {
		fprintf(stderr, "%s: bad reminder contents\n", program);
		return 20;
	}
	t = drew_mem_malloc(strlen(s));
	if (flags & FLAG_EXPLICIT_VERSION) {
		if (sscanf(s+off, "%02x", &format) != 1) {
			fprintf(stderr, "%s: bad reminder format\n", program);
			return 20;
		}
		off += 2;
	}
	if (format) {
		fprintf(stderr, "%s: unknown format %d\n", program, format);
		return 20;
	}
	if (sscanf(s+off, "%02x%02x%s", &size, &version, t) != 3 || (size & 0x80) ||
			(version & 0x80)) {
		fprintf(stderr, "%s: bad reminder contents\n", program);
		return 20;
	}
	generate_password(c, d, t, flags, version, size, 0);
	drew_mem_free(t);
	return 0;
}

int main(int argc, char **argv)
{
	int retval = 0, ch;
	struct crypto c;
	struct data *d;

	program = argv[0];

	d = drew_mem_scalloc(1, sizeof(*d));
	d->flags = FLAG_NO_SPACES | FLAG_NO_SYMBOLS_OTHER;

	while ((ch = getopt(argc, argv, "f:v:l:")) > 0) {
		switch (ch) {
			case 'f':
				d->flags = atoi(optarg);
				break;
			case 'v':
				d->version = atoi(optarg);
				break;
			case 'l':
				d->length = atoi(optarg);
				break;
		}
	}
	if (!d->length)
		d->length = 16;

	if ((retval = set_up_crypto(&c)))
		goto out;

	if ((retval = get_master_secret(&c, d)))
		goto out;

	calculate_quick_check(&c, d);
	printf("# ok, checksum is %s\n", d->qc);

	if (optind < argc) {
		while (optind < argc)
			if ((retval = generate_password_from_reminder(&c, d,
							argv[optind++])))
				goto out;
	}
	else {
		char buf[BUFFER_SIZE];
		while (!get_code(buf, sizeof(buf)))
			generate_password(&c, d, buf, d->flags, d->version, d->length, 1);
	}

out:
	drew_mem_sfree(d);
	free_crypto(&c);
	return retval;
}
