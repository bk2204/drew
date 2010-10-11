include config

#MD_SRC-${CFG_SHA1}		+= sha1.c md-pad.c
#MD_SRC-${CFG_SHA256}	+= sha256.c md-pad.c
#MD_SRC-${CFG_RMD160}	+= ripe160.c md-pad.c
#MD_SRC-${CFG_MD5}		+= md5.c md-pad.c
#MD_SRC-${CFG_MD4}		+= md4.c md-pad.c
#MD_SRC-${CFG_MD2}		+= md2.c
#
#MD_MODS					:= SHA1 RMD160 MD5 MD4 MD2 SHA256
#
#.for i in ${MD_MODS}
#CFLAGS-${CFG_$i}		+= -DCFG_$i
#.endfor
#
#MD_OBJS			:= ${MD_SRC-y:O:u:.c=.o}

CATEGORIES		:= hash block mode

TEST_SRC		+= libmd/testsuite.c
TEST_OBJ		:= ${SRC:.c=.o} ${TEST_SRC:.c=.o}
TEST_EXE		:= libmd/testsuite

PLUG_SRC		+= plugin-main.c
PLUG_OBJ		:= ${SRC:.c=.p} ${PLUG_SRC:.c=.o}
PLUG_EXE		:= plugin-main

TEST_BINARIES	:= $(patsubst %,test/test-%,$(CATEGORIES))

DREW_SONAME		:= libdrew.so.0
DREW_SYMLINK	:= $(basename $(DREW_SONAME))

RM				?= rm

ifdef PROF
CLIKEFLAGS		+= -pg
endif
CPPFLAGS		+= -Iinclude
CLIKEFLAGS		+= -Wall -fPIC -O3 -g -pipe
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

all: ${PLUG_EXE} ${DREW_SONAME} standard

include impl/hash/Makefile
include impl/block/Makefile
include impl/mode/Makefile
include libmd/Makefile

standard: ${DREW_SONAME} ${MD_SONAME} plugins libmd/testsuite
standard: $(TEST_BINARIES)

${DREW_SONAME}: plugin.o
	${CC} ${CFLAGS} ${LIBCFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${DREW_SYMLINK}: ${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}

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

test/test-%: test/test-%.o test/framework.o ${DREW_SONAME} 
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

test: .PHONY

test check: test-scripts test-libmd
speed speed-test: speed-scripts

test-libmd: ${TEST_EXE}
	env LD_LIBRARY_PATH=. ./${TEST_EXE} -x | \
		grep -v 'bytes in' | diff -u libmd/test-results -

test-scripts:
	for i in hash block mode; do \
		ls -1 plugins/* | sed -e 's,.*/,,g' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -i; \
		done

speed-scripts:
	for i in hash block mode; do \
		ls -1 plugins/* | sed -e 's,.*/,,g' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -s; \
		done
