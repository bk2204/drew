#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/parser.h>

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

int list_packets(const char *filename)
{
	uint8_t *buf;
	int fd, res = 0;
	struct stat st;
	off_t off = 0;
	drew_opgp_parser_t pars;
	drew_opgp_packet_t pkt;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return print_error(16, errno, "couldn't open %s", filename);
	if (fstat(fd, &st))
		return print_error(17, errno, "couldn't fstat %s", filename);
	buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		return print_error(18, errno, "couldn't mmap %s", filename);
	drew_opgp_parser_new(&pars, 0, NULL);
	while (res >= 0 && off < st.st_size) {
		res = drew_opgp_parser_parse_packet(pars, &pkt, buf+off,
				st.st_size-off);
		if (res < 0) {
			res = print_error(19, res, "failed parsing packet");
			goto out;
		}
		off += res;
		print_packet(&pkt);
	}
	res = 0;
out:
	drew_opgp_parser_free(&pars);
	return res;
}

int main(int argc, char **argv)
{
	programname = argv[0];
	if (argc < 3) {
		fprintf(stderr, "%s: need at least two arguments\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "--list-packets")) {
		return list_packets(argv[2]);
	}
	else {
		fprintf(stderr, "%s: only --list-packets is supported\n", argv[0]);
		return 3;
	}
	return 0;
}
