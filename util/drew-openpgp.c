#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
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
	fprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", drew_strerror(error));
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
	else if (!(flags & DREW_OPGP_SIGNATURE_CHECKED))
		c = '?';
	else
		switch (flags & (DREW_OPGP_SIGNATURE_HASH_CHECK | 
					DREW_OPGP_SIGNATURE_VALIDATED))
		{
			case 0:
				c = '?';
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
			print_key_signature_info(sigs[i]);
	}
	free(uids);
}

int print_fingerprint(struct file *f, struct util *util)
{
	int res = 0;
	size_t off = 0, toff;
	// FIXME: do not hardcode this.
	drew_opgp_packet_t pkts[50];
	drew_opgp_key_t key;
	size_t npkts = DIM(pkts), nused = 0, nparsed = 1;

	memset(pkts, 0, sizeof(pkts));
	while (off < f->size || nparsed || pkts[0].type) {
		npkts = DIM(pkts) - nused;
		res = drew_opgp_parser_parse_packets(util->pars, pkts+nused, &npkts,
				f->buf+off, f->size-off, &toff);
		if (res < 0) {
			res = print_error(19, res, "failed parsing packets");
			goto out;
		}
		off += toff;
		nparsed = npkts;
		drew_opgp_key_new(&key, util->ldr);
		if ((res = drew_opgp_key_load_public(key, pkts, npkts+nused)) < 0) {
			res = print_error(20, res, "failed loading packets");
			goto out;
		}
		nused = res;
		if ((res = drew_opgp_key_synchronize(key,
						DREW_OPGP_SYNCHRONIZE_ALL|DREW_OPGP_SYNCHRONIZE_FORCE))
				< 0) {
			res = print_error(21, res, "failed to synchronize");
			goto out;
		}
		print_key_info(key);
		drew_opgp_key_free(&key);
		res = 0;
		for (size_t i = nused; i < DIM(pkts) && pkts[i].type &&
				pkts[i].type != 6; i++, nused++);
		size_t rem = DIM(pkts) - nused;
		memmove(pkts, pkts+nused, rem * sizeof(*pkts));
		memset(pkts+rem, 0, nused * sizeof(*pkts));
	}
out:
	return res;
}

int main(int argc, char **argv)
{
	int res = 0;
	struct file f;
	struct util util;
	programname = argv[0];
	if (argc < 3) {
		fprintf(stderr, "%s: need at least two arguments\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "--list-packets")) {
		if ((res = open_file(&f, argv[2])))
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
	else if (!strcmp(argv[1], "--fingerprint")) {
		if ((res = open_file(&f, argv[2])))
			return res;
		if ((res = create_util(&util))) {
			close_file(&f);
			return res;
		}
		res = print_fingerprint(&f, &util);
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
