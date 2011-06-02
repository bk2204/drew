UTILS			:= sha512sum

UTILITIES		:= $(patsubst %,util/%,$(UTILS))

util/%: util/%.o $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) -o $(.TARGET) $(.ALLSRC) $(LIBS)
