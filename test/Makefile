TEST_BINARIES	:= $(patsubst %,test/test-%,$(CATEGORIES))

test/test-%: test/test-%.o test/framework.o ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}
