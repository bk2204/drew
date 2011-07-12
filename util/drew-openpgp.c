#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <popt.h>

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/keystore.h>
#include <drew-opgp/parser.h>
#include <drew-opgp/sig.h>

#define DIM(x) (sizeof(x)/sizeof(x[0]))

const char *programname;

// This is not thread-safe.
const char *drew_strerror(int res)
{
	static char buf[512];
	div_t d;
	res = abs(res);
	if (res < 65536)
		return strerror(res);
	d = div(res, 65536);
	snprintf(buf, sizeof(buf), "error code %d (%d:%d)", res, d.quot, d.rem);
	return buf;
}

int print_error(int retval, int error, const char *msg, ...)
{
	va_list ap;
	fprintf(stderr, "%s: ", programname);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	if (error)
		fprintf(stderr, ": %s", drew_strerror(error));
	fprintf(stderr, "\n");
	return retval;
}

void print_packet(const drew_opgp_packet_t *pkt)
{
	printf("%s: %s(tag %d)(%lld bytes)\n", pkt->ver > 3 ? "New" : "Old",
			"Packet", pkt->type, pkt->len);
	if (pkt->type == 13) {
		printf("\tUser ID - ");
		fwrite(pkt->data.data.data, 1, pkt->data.data.len, stdout);
		putchar('\n');
	}
}

struct file {
	uint8_t *buf;
	int fd;
	off_t size;
	const char *filename;
};

struct util {
	drew_loader_t *ldr;
	drew_opgp_parser_t pars;
};

int open_file(struct file *f, const char *filename)
{
	struct stat st;
	if ((f->fd = open(filename, O_RDONLY)) < 0)
		return print_error(16, errno, "couldn't open %s", filename);
	if (fstat(f->fd, &st))
		return print_error(17, errno, "couldn't fstat %s", filename);
	f->size = st.st_size;
	f->buf = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, f->fd, 0);
	if (f->buf == MAP_FAILED)
		return print_error(18, errno, "couldn't mmap %s", filename);
	f->filename = filename;
	return 0;
}

void close_file(struct file *f)
{
	munmap(f->buf, f->size);
	close(f->fd);
}

int create_util(struct util *util)
{
	int res = 0;
	const char *pluginnames[] = {
		"md5",
		"md2",
		"sha1",
		"sha256",
		"sha512",
		"ripe160",
		"blowfish",
		"aes",
		"camellia",
		"des",
		"cast5"
	};

	if ((res = drew_loader_new(&util->ldr)))
		return print_error(5, res, "couldn't create loader");
	drew_loader_load_plugin(util->ldr, NULL, NULL);
	for (size_t i = 0; i < DIM(pluginnames); i++) {
		drew_loader_load_plugin(util->ldr, pluginnames[i], NULL);
		drew_loader_load_plugin(util->ldr, pluginnames[i], "./plugins");
	}
	if ((res = drew_opgp_parser_new(&util->pars, 0, NULL))) {
		drew_loader_free(&util->ldr);
		return print_error(6, res, "couldn't create packet parser");
	}
	return 0;
}

void destroy_util(struct util *util)
{
	drew_opgp_parser_free(&util->pars);
	drew_loader_free(&util->ldr);
}

int list_packets(struct file *f, struct util *util)
{
	int res = 0;
	off_t off = 0;
	drew_opgp_packet_t pkt;

	while (res >= 0 && off < f->size) {
		res = drew_opgp_parser_parse_packet(util->pars, &pkt, f->buf+off,
				f->size-off);
		if (res < 0) {
			res = print_error(19, res, "failed parsing packet");
			goto out;
		}
		off += res;
		print_packet(&pkt);
	}
	res = 0;
out:
	return res;
}

void print_key_signature_info(drew_opgp_sig_t sig)
{
	drew_opgp_keyid_t keyid;
	int flags;
	char c, rev = ' ', exp = ' ', loc = ' ', self = ' ';
	drew_opgp_sig_get_flags(sig, &flags, 1);
	drew_opgp_sig_get_issuer(sig, keyid);
	if (flags & DREW_OPGP_SIGNATURE_CORRUPT)
		c = '-';
	else if (flags & DREW_OPGP_SIGNATURE_INCOMPLETE)
		c = '-';
	else if (flags & DREW_OPGP_SIGNATURE_CHECKED)
		switch (flags & (DREW_OPGP_SIGNATURE_HASH_CHECK | 
					DREW_OPGP_SIGNATURE_VALIDATED))
		{
			case 0:
				c = 'x';
				break;
			case DREW_OPGP_SIGNATURE_HASH_CHECK:
				c = 'h';
				break;
			case DREW_OPGP_SIGNATURE_VALIDATED:
				c = 'V';
				break;
			default:
				c = 'v';
				break;
		}
	else if (flags & DREW_OPGP_SIGNATURE_HASH_CHECK)
		c = 'p';
	else
		c = '?';

	if (flags & DREW_OPGP_SIGNATURE_IRREVOCABLE)
		rev = '!';
	else if (flags & DREW_OPGP_SIGNATURE_REVOKED)
		rev = 'x';
	if (flags & DREW_OPGP_SIGNATURE_EXPIRED)
		exp = 't';
	if (flags & DREW_OPGP_SIGNATURE_LOCAL)
		loc = 'p';
	printf("        Signature: %c%c%c%c%c ", c, self, rev, exp, loc);
	for (size_t i = 0; i < sizeof(keyid); i++)
		printf("%02x", keyid[i]);
	printf("\n");
}

void print_key_info(drew_opgp_key_t key)
{
	drew_opgp_fp_t fp;
	drew_opgp_id_t id;
	drew_opgp_keyid_t keyid;
	int version, nuids, nsigs;
	drew_opgp_uid_t *uids;
	drew_opgp_sig_t *sigs;
	version = drew_opgp_key_get_version(key);
	drew_opgp_key_get_fingerprint(key, fp);
	drew_opgp_key_get_id(key, id);
	drew_opgp_key_get_keyid(key, keyid);
	printf("Key ");
	for (size_t i = 0; i < 32; i++)
		printf("%02x", id[i]);
	printf(":\n    Info:    %d ", version);
	for (size_t i = 0; i < 8; i++)
		printf("%02x", keyid[i]);
	printf(" ");
	for (size_t i = 0; i < (version < 4 ? 16 : 20); i++)
		printf("%02x", fp[i]);
	printf("\n");
	nuids = drew_opgp_key_get_user_ids(key, &uids);
	for (int i = 0; i < nuids; i++) {
		const char *text;
		drew_opgp_uid_get_text(uids[i], &text);
		printf("    User ID: %s\n", text);
		nsigs = drew_opgp_uid_get_signatures(uids[i], &sigs);
		for (int j = 0; j < nsigs; j++)
			print_key_signature_info(sigs[j]);
	}
	free(uids);
}

int print_fingerprint(struct file *f, struct util *util, size_t pktbufsz)
{
	int res = 0;
	size_t off = 0, toff;
	drew_opgp_packet_t *pkts;
	drew_opgp_key_t key;
	size_t npkts = pktbufsz, nused = 0, nparsed = 1;
	size_t fill = 0;

	pkts = malloc(sizeof(*pkts) * pktbufsz);

	memset(pkts, 0, sizeof(*pkts) * pktbufsz);
	while (off < f->size || nparsed || pkts[0].type) {
		npkts = pktbufsz - fill;
		res = drew_opgp_parser_parse_packets(util->pars, pkts+fill, &npkts,
				f->buf+off, f->size-off, &toff);
		if (res < 0) {
			res = print_error(19, res, "failed parsing packets");
			goto out;
		}
		off += toff;
		nparsed = npkts;
		fill += nparsed;
		if (!pkts[0].type)
			break;
		drew_opgp_key_new(&key, util->ldr);
		if ((res = drew_opgp_key_load_public(key, pkts, fill)) < 0) {
			res = print_error(20, res, "failed loading packets");
			goto out;
		}
		nused = res;
		if (nused) {
			if ((res = drew_opgp_key_synchronize(key,
							DREW_OPGP_SYNCHRONIZE_ALL|
							DREW_OPGP_SYNCHRONIZE_FORCE))
					< 0) {
				res = print_error(21, res, "failed to synchronize");
				goto out;
			}
			print_key_info(key);
		}
		else
			return print_error(22, 0,
					"packet buffer (%zu packets) is too small", pktbufsz);
		drew_opgp_key_free(&key);
		res = 0;
		for (size_t i = nused; i < pktbufsz && pkts[i].type &&
				pkts[i].type != 6; i++, nused++);
		size_t rem = pktbufsz - nused;
		memmove(pkts, pkts+nused, rem * sizeof(*pkts));
		memset(pkts+rem, 0, nused * sizeof(*pkts));
		fill = rem;
	}
out:
	free(pkts);
	return res;
}

int import(struct file *f, struct util *util, size_t pktbufsz,
		const char *keystorefile)
{
	int res = 0;
	size_t off = 0, toff;
	drew_opgp_packet_t *pkts;
	drew_opgp_key_t key;
	drew_opgp_keystore_t ks;
	size_t npkts = pktbufsz, nused = 0, nparsed = 1;
	size_t fill = 0;

	pkts = malloc(sizeof(*pkts) * pktbufsz);

	memset(pkts, 0, sizeof(*pkts) * pktbufsz);
	drew_opgp_keystore_new(&ks, util->ldr);
	while (off < f->size || nparsed || pkts[0].type) {
		npkts = pktbufsz - fill;
		res = drew_opgp_parser_parse_packets(util->pars, pkts+fill, &npkts,
				f->buf+off, f->size-off, &toff);
		if (res < 0) {
			res = print_error(19, res, "failed parsing packets");
			goto out;
		}
		off += toff;
		nparsed = npkts;
		fill += nparsed;
		if (!pkts[0].type)
			break;
		drew_opgp_key_new(&key, util->ldr);
		if ((res = drew_opgp_key_load_public(key, pkts, fill)) < 0) {
			res = print_error(20, res, "failed loading packets");
			goto out;
		}
		nused = res;
		if (nused) {
			if ((res = drew_opgp_key_synchronize(key,
							DREW_OPGP_SYNCHRONIZE_ALL|
							DREW_OPGP_SYNCHRONIZE_FORCE))
					< 0) {
				res = print_error(21, res, "failed to synchronize");
				goto out;
			}
			print_key_info(key);
		}
		else
			return print_error(22, 0,
					"packet buffer (%zu packets) is too small", pktbufsz);
		drew_opgp_keystore_update_key(ks, key, 0);
		//drew_opgp_key_free(&key);
		res = 0;
		for (size_t i = nused; i < pktbufsz && pkts[i].type &&
				pkts[i].type != 6; i++, nused++);
		size_t rem = pktbufsz - nused;
		memmove(pkts, pkts+nused, rem * sizeof(*pkts));
		memset(pkts+rem, 0, nused * sizeof(*pkts));
		fill = rem;
	}
out:
	drew_opgp_keystore_set_backend(ks, "file");
	printf("Saving keystore...");
	fflush(stdout);
	if ((res = drew_opgp_keystore_store(ks, keystorefile)))
		return print_error(23, res, "keystore failure");
	drew_opgp_keystore_free(&ks);
	printf("done.\n");
	free(pkts);
	return res;
}

int main(int argc, char **argv)
{
	int res = 0, cmd = 0, pktbufsz = 500;
	struct file f;
	struct util util;
	const char *keystorefile = NULL;
	struct poptOption optsargs[] = {
		{"list-packets", 0, POPT_ARG_VAL, &cmd, 1, NULL, NULL},
		{"fingerprint", 0, POPT_ARG_VAL, &cmd, 2, NULL, NULL},
		{"import", 0, POPT_ARG_VAL, &cmd, 3, NULL, NULL},
		{"keystore", 0, POPT_ARG_STRING, &keystorefile, 1, NULL, NULL},
		{"packet-buffer-size", 0, POPT_ARG_INT, &pktbufsz, 0, NULL, NULL},
		POPT_TABLEEND
	};
	const char *filename = NULL;
	poptContext ctx;

	programname = argv[0];
	ctx = poptGetContext(programname, argc, argv, optsargs, 0);
	while (poptGetNextOpt(ctx) >= 0);
	filename = poptGetArg(ctx);
	poptFreeContext(ctx);

	if (!filename)
		return 5;
	if (cmd == 1) {
		if ((res = open_file(&f, filename)))
			return res;
		if ((res = create_util(&util))) {
			close_file(&f);
			return res;
		}
		res = list_packets(&f, &util);
		destroy_util(&util);
		close_file(&f);
		return res;
	}
	else if (cmd == 2) {
		if ((res = open_file(&f, filename)))
			return res;
		if ((res = create_util(&util))) {
			close_file(&f);
			return res;
		}
		res = print_fingerprint(&f, &util, pktbufsz);
		destroy_util(&util);
		close_file(&f);
		return res;
	}
	else if (cmd == 3) {
		if (!keystorefile)
			return 32;
		if ((res = open_file(&f, filename)))
			return res;
		if ((res = create_util(&util))) {
			close_file(&f);
			return res;
		}
		res = import(&f, &util, pktbufsz, keystorefile);
		destroy_util(&util);
		close_file(&f);
		return res;
	}
	else {
		fprintf(stderr, "%s: only --list-packets is supported\n", argv[0]);
		return 3;
	}
	return 0;
}
