SUMS					:= md5 sha1 sha224 sha256 sha384 sha512
SUMS_PROGS				:= $(patsubst %,util/%sum,$(SUMS))

UTILS					+= daniel version
UTILITIES				:= $(patsubst %,util/%,$(UTILS))
UTILITIES				+= $(SUMS_PROGS)

$(SUMS_PROGS:=.o): util/sum.c

util/%: util/%.o | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $@ $^ $| $(LIBS)
