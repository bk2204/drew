SUMS					:= md5 sha1 sha224 sha256 sha384 sha512
SUMS_PROGS				:= $(patsubst %,util/drew-%sum,$(SUMS))

UTILS					+= daniel drew-config
UTILITIES				:= $(patsubst %,util/%,$(UTILS))
UTILITIES				+= $(SUMS_PROGS)

$(SUMS_PROGS:=.o): util/sum.c

util/drew-config: LIBS += -lpopt

util/drew-%: util/%.o | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $@ $^ $| $(LIBS)

util/daniel: util/daniel.o | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $@ $^ $| $(LIBS)
