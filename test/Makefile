TEST_SPECIAL	:= prng
TEST_SPECIALBIN	:= $(patsubst %,test/test-%,$(TEST_SPECIAL))
TEST_STANDARD	:= $(filter-out $(TEST_SPECIAL),$(CATEGORIES))
TEST_STDBIN		:= $(patsubst %,test/test-%,$(TEST_STANDARD))
TEST_OTHER		:= mem
TEST_OTHERBIN	:= $(patsubst %,test/test-%,$(TEST_OTHER))

TEST_BINARIES	:= $(TEST_SPECIALBIN) $(TEST_STDBIN) $(TEST_OTHERBIN)

$(TEST_STDBIN):		test/external.o
$(TEST_STDBIN):		test/framework.o $(DREW_SONAME) $(DREW_IMPL_SONAME)
$(TEST_SPECIALBIN):	test/framework.o $(DREW_SONAME) $(DREW_IMPL_SONAME)

test/test-prng: LIBS += -lm
test/test-mem: $(DREW_SONAME)

test/test-%: test/test-%.o
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}
