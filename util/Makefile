SUMS			:= md5 sha1 sha224 sha256 sha384 sha512

UTILS			+= $(patsubst %,%sum,$(SUMS))

UTILITIES		:= $(patsubst %,util/%,$(UTILS))

# FIXME: only for SUMS, not all future utilities.
$(UTILITIES:=.o): util/sum.c

util/%: util/%.o $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $(.TARGET) $(.ALLSRC) $(LIBS)
