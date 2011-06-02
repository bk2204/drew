SUMS			:= sha512 md5

UTILS			+= $(patsubst %,%sum,$(SUMS))

UTILITIES		:= $(patsubst %,util/%,$(UTILS))

# FIXME: only for SUMS, not all future utilities.
$(UTILITIES:=.o): util/sum.c

util/%: util/%.o $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $(.TARGET) $(.ALLSRC) $(LIBS)
