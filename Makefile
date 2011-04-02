include config

CATEGORIES		:= hash block mode mac stream prng

TEST_SRC		+= libmd/testsuite.c
TEST_OBJ		:= ${SRC:.c=.o} ${TEST_SRC:.c=.o}
TEST_EXE		:= libmd/testsuite

PLUG_SRC		+= test/plugin-main.c
PLUG_OBJ		:= ${SRC:.c=.o} ${PLUG_SRC:.c=.o}
PLUG_EXE		:= test/plugin-main

TEST_BINARIES	:= $(patsubst %,test/test-%,$(CATEGORIES))

RM				?= rm

ifdef PROF
CLIKEFLAGS		+= -pg
endif
CPPFLAGS		+= -Iinclude
CLIKEFLAGS		+= -Wall -fPIC -O3 -g -pipe -D_POSIX_SOURCE=200112L -D_XOPEN_SOURCE=600
CLIKEFLAGS		+= -Wunsafe-loop-optimizations -funsafe-loop-optimizations
CLIKEFLAGS		+= -fmodulo-sched -fmodulo-sched-allow-regmoves
CLIKEFLAGS		+= -fsched-pressure
CLIKEFLAGS		+= ${CFLAGS-y}
CXXFLAGS		:= ${CLIKEFLAGS}
CFLAGS			:= ${CLIKEFLAGS}
CXXFLAGS		+= -fno-rtti -fno-exceptions
CFLAGS			+= -std=c99

LIBCFLAGS		+= -shared
PLUGINCFLAGS	+= -I.

LDFLAGS			+= -Wl,--version-script,misc/limited-symbols.ld -Wl,--as-needed
LIBS			+= ${LDFLAGS} -lrt -ldl

.TARGET			= $@
.ALLSRC			= $^
.IMPSRC			= $<

all:

include lib/libdrew/Makefile
include $(patsubst %,impl/%/Makefile,$(CATEGORIES))
include lib/libdrew-impl/Makefile
include libmd/Makefile

all: ${PLUG_EXE} ${DREW_SONAME} standard

standard: ${DREW_SONAME} ${MD_SONAME} plugins libmd/testsuite
standard: $(TEST_BINARIES)

${TEST_EXE}: ${TEST_SRC} ${MD_SONAME} ${DREW_SONAME}
	${CC} -Ilibmd/include ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${PLUG_EXE}: ${PLUG_OBJ} ${DREW_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

.c.o:
	${CC} ${CPPFLAGS} ${CFLAGS} -c -o ${.TARGET} ${.IMPSRC}

.cc.o:
	${CXX} ${CPPFLAGS} ${CXXFLAGS} -c -o ${.TARGET} ${.IMPSRC}

${PLUGINS:=.o}: CPPFLAGS += ${PLUGINCFLAGS}

${PLUGINS}: %: %.so
	@:

$(PLUGINS:=.so): %.so: %.o
	${CXX} ${LIBCFLAGS} ${CXXFLAGS} -o ${.TARGET} ${.ALLSRC} ${LDFLAGS}

test/test-%: test/test-%.o test/framework.o ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

plugins: ${PLUGINS}
	[ -d plugins ] || mkdir plugins
	for i in ${.ALLSRC}; do cp $$i.so plugins/`basename $$i .so`; done

clean:
	${RM} -f *.o test/*.o
	${RM} -f ${TEST_EXE}
	${RM} -f ${PLUG_EXE}
	${RM} -f ${MD_SONAME} ${MD_OBJS}
	${RM} -f ${DREW_SONAME} ${DREW_SYMLINK}
	${RM} -f ${TEST_BINARIES}
	${RM} -fr ${PLUGINS} plugins/
	find -name '*.o' | xargs -r rm
	find -name '*.so' | xargs -r rm
	find -name '*.so.*' | xargs -r rm

test: .PHONY

test check: test-scripts testx-scripts test-libmd
speed speed-test: speed-scripts

test-libmd: ${TEST_EXE}
	env LD_LIBRARY_PATH=. ./${TEST_EXE} -x | \
		grep -v 'bytes in' | diff -u libmd/test-results -

test-scripts: $(TEST_BINARIES) plugins
	for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -i; \
		done

testx-scripts: $(TEST_BINARIES) plugins
	for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -t; \
		done

speed-scripts: $(TEST_BINARIES) plugins
	for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -s; \
		done
