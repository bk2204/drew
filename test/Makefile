TEST_SPECIAL	:= prng
TEST_SPECIALBIN	:= $(patsubst %,test/test-%,$(TEST_SPECIAL))
TEST_STANDARD	:= $(filter-out $(TEST_SPECIAL),$(CATEGORIES))
TEST_STDBIN		:= $(patsubst %,test/test-%,$(TEST_STANDARD))

TEST_BINARIES	:= $(TEST_SPECIALBIN) $(TEST_STDBIN)

$(TEST_STDBIN): test/external.o

test/test-prng: LIBS += -lm

test/test-%: test/test-%.o test/framework.o ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}
