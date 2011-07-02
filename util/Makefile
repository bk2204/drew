SUMS					:= md5 sha1 sha224 sha256 sha384 sha512
SUMS_PROGS				:= $(patsubst %,util/drew-%sum,$(SUMS))

UTILS					+= daniel drew-config drew-sum
UTILS					+= drew-x509
UTILITIES				:= $(patsubst %,util/%,$(UTILS))
UTILITIES				+= $(SUMS_PROGS)

$(SUMS_PROGS:=.o): util/sum.c

util/drew-config: LIBS += -lpopt
util/drew-x509: $(DREW_UTIL_SONAME)

util/drew-%: util/%.o | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $@ $^ $| $(LIBS)

util/daniel: util/daniel.o | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $@ $^ $| $(LIBS)
