include config

CATEGORIES		:= hash block mode mac stream prng bignum pkenc pksig kdf

TEST_SRC		+= libmd/testsuite.c
TEST_OBJ		:= ${SRC:.c=.o} ${TEST_SRC:.c=.o}
TEST_EXE		:= libmd/testsuite

PLUG_SRC		+= test/plugin-main.c
PLUG_OBJ		:= ${SRC:.c=.o} ${PLUG_SRC:.c=.o}
PLUG_EXE		:= test/plugin-main

RM				?= rm
RMDIR			?= rmdir

INSTALL_PROG	?= install
INSTALL_OPTS	:= $(shell [ `id -u` -eq 0 ] && printf -- "-o root -g root\n" || printf "\n")
INSTALL			:= $(INSTALL_PROG) $(INSTALL_OPTS)

ifdef PROF
CLIKEFLAGS		+= -pg
endif
ifeq ($(CFG_THREAD_SAFE),y)
CLIKEFLAGS		+= -D_REENTRANT -D_THREAD_SAFE
endif
ifeq ($(CFG_FORTIFY),y)
CLIKEFLAGS		+= -D_FORTIFY_SOURCE=2
endif
ifeq ($(CFG_STACK_CHECK),y)
CLIKEFLAGS		+= -fstack-protector
endif

CPPFLAGS		+= -Iinclude
CLIKEFLAGS		+= -Wall -fPIC -O3 -g -pipe
CLIKEFLAGS		+= -D_POSIX_SOURCE=200112L -D_XOPEN_SOURCE=600
CLIKEFLAGS		+= -fextended-identifiers
CLIKEFLAGS		+= -floop-interchange -floop-block
CLIKEFLAGS		+= -fvisibility=hidden
CLIKEFLAGS		+= ${CFLAGS-y}
CXXFLAGS		:= ${CLIKEFLAGS}
CFLAGS			:= ${CLIKEFLAGS}
CXXFLAGS		+= -fno-rtti
CFLAGS			+= -std=c99

LIBCFLAGS		+= -shared
PLUGINCFLAGS	+= -I.

LDFLAGS			+= -Wl,--as-needed
LIBS			+= ${LDFLAGS} -lrt -ldl

.TARGET			= $@
.ALLSRC			= $^
.IMPSRC			= $<

all:

include lib/libdrew/Makefile
include lib/libdrew-util/Makefile
include $(patsubst %,impl/%/Makefile,$(CATEGORIES))
include lib/libdrew-impl/Makefile
include test/Makefile
include util/Makefile
include libmd/Makefile
include doc/manual/Makefile

OBJECTS			+= $(PLUGINS:=.o) $(MODULES)
OBJECTS			+= $(EXTRA_OBJECTS-y) $(EXTRA_OBJECTS-m)

DEPFILES		:= $(OBJECTS:.o=.d)

all: ${PLUG_EXE} ${DREW_SONAME} standard

depend: $(DEPFILES)

standard: ${DREW_SONAME} ${MD_SONAME} plugins libmd/testsuite
standard: $(DREW_UTIL_SONAME)
standard: $(TEST_BINARIES) $(UTILITIES)

${TEST_EXE}: ${TEST_SRC} ${MD_SONAME} ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} -Ilibmd/include ${CPPFLAGS} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${PLUG_EXE}: ${PLUG_OBJ} ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

.c.o:
	${CC} ${CPPFLAGS} ${CFLAGS} -c -o ${.TARGET} ${.IMPSRC}

.cc.o:
	${CXX} ${CPPFLAGS} ${CXXFLAGS} -c -o ${.TARGET} ${.IMPSRC}

%.d: %.c
	$(CC) $(CPPFLAGS) -MM $< | sed -e 's,$(*F)\.o:,$*.o $@:,g' > $@

%.d: %.cc
	$(CC) $(CPPFLAGS) -MM $< | sed -e 's,$(*F)\.o:,$*.o $@:,g' > $@

${PLUGINS:=.o}: CPPFLAGS += ${PLUGINCFLAGS}

${PLUGINS}: %: %.so
	@:

$(PLUGINS:=.so): %.so: %.o
	${CXX} ${LIBCFLAGS} ${CXXFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

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
	${RM} -f ${UTILITIES}
	${RM} -fr ${PLUGINS} plugins/
	${RM} -r install
	find -name '*.o' | xargs -r rm
	find -name '*.d' | xargs -r rm
	find -name '*.so' | xargs -r rm
	find -name '*.so.*' | xargs -r rm
	find -name '*.pdf' | xargs -r rm
	find -name '*.fo' | xargs -r rm

test: .PHONY

test check: test-scripts testx-scripts test-libmd
speed speed-test: speed-scripts

test-libmd: ${TEST_EXE}
	env LD_LIBRARY_PATH=. ./${TEST_EXE} -x | \
		grep -v 'bytes in' | diff -u libmd/test-results -

test-scripts: $(TEST_BINARIES) plugins
	set -e; for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -i; \
		done

testx-scripts: $(TEST_BINARIES) plugins
	set -e; for i in $(CATEGORIES); do \
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

install: .PHONY

INSTDIR			:= $(CFG_INSTALL_DIR)

install: all
	$(INSTALL) -m 755 -d $(INSTDIR)/lib/drew/plugins
	$(INSTALL) -m 755 -d $(INSTDIR)/include
	for i in plugins/*; do $(INSTALL) -m 644 $$i $(INSTDIR)/lib/drew/plugins; done
	$(INSTALL) -m 644 libdrew*.so.* $(INSTDIR)/lib
	for i in include/*; do \
		[ -f $$i ] || \
			($(INSTALL) -m 755 -d $(INSTDIR)/$$i; \
			$(INSTALL) -m 644 $$i $(INSTDIR)/include);\
		done
	$(INSTALL) -m 644 include/drew/* $(INSTDIR)/include/drew

uninstall:
	$(RM) $(INSTDIR)/lib/libdrew*.so.*
	for i in plugins/*; do $(RM) $(INSTDIR)/lib/drew/$$i; done
	for i in include/*; do \
		[ -f $$i ] || \
			($(RM) $(INSTDIR)/$$i/*.h; $(RMDIR) $(INSTDIR)/$$i); \
		done
	$(RMDIR) $(INSTDIR)/lib/drew/plugins || true
	$(RMDIR) $(INSTDIR)/lib/drew || true

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPFILES)
endif
