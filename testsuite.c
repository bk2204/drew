/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different message digest
 * algorithms.  This implementation requires ANSI C and POSIX timers.
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <md4.h>
#include <md5.h>
#include <ripe160.h>
#include <sha1.h>
#include <sha256.h>

static const char *strings[]={
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"1234567890123456789012345678901234567890"
	"1234567890123456789012345678901234567890"
};

#define CHUNK 8192
#define NCHUNKS 40960

#define TESTSUITE(x) TestMD(#x, x##Data)
void TestMD(const char *name, char *(*data)(const uint8_t *, size_t, char *))
{
	size_t i;
	for (i=0; i<sizeof(strings)/sizeof(strings[0]); i++) {
		char buf[1024/8];
		printf("%s (\"%s\") = %s\n", name, strings[i],
				data((const uint8_t *)strings[i],
					strlen(strings[i]), buf));
	}
}
#define TIMETEST(x) TimeMD(#x, sizeof(x##_CTX), x##Init, x##Update, x##Final)
void TimeMD(const char *name, size_t ctxsz, void (*init)(hash_ctx_t *),
	void (*update)(hash_ctx_t *, const uint8_t *, size_t),
	void (*final)(uint8_t *, hash_ctx_t *))
{
	unsigned char *buf;
	struct timespec cstart, cend;
	double diff, rate, start, end;
	size_t i;
	void *ctx;
	if (!(ctx=malloc(ctxsz)))
		return;
	if (!(buf=calloc(CHUNK, 1))) {
		free(ctx);
		return;
	}
	clock_gettime(CLOCK_REALTIME, &cstart);
	init(ctx);
	for (i=0; i<NCHUNKS; i++)
		update(ctx, buf, CHUNK);
	final(buf, ctx);
	clock_gettime(CLOCK_REALTIME, &cend);
	free(buf);
	free(ctx);
	start=cstart.tv_sec+(cstart.tv_nsec/1000000000.0);
	end=cend.tv_sec+(cend.tv_nsec/1000000000.0);
	diff=end-start;
	rate=CHUNK*(double)NCHUNKS/diff;
	rate/=1048576;
	printf("%s: %d bytes in %0.3fs (%0.3f MiB/s)\n", name, (NCHUNKS*CHUNK),
			diff, rate);
}


int main(int argc, char **argv)
{
	if (argc<2 || !strcmp(argv[1], "-x")) {
		TESTSUITE(MD4);
		TESTSUITE(MD5);
		TESTSUITE(RMD160);
		TESTSUITE(SHA1);
		TESTSUITE(SHA256);
	}
	else {
		TIMETEST(MD4);
		TIMETEST(MD5);
		TIMETEST(RMD160);
		TIMETEST(SHA1);
		TIMETEST(SHA256);
	}
	return 0;
}
