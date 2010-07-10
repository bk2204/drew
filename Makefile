.include "config"

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

TEST_SRC		+= testsuite.c

TEST_OBJ		:= ${SRC:O:u:.c=.o} ${TEST_SRC:.c=.o}
TEST_EXE		:= testsuite

PLUG_SRC		+= plugin-main.c
PLUG_OBJ		:= ${SRC:O:u:.c=.p} ${PLUG_SRC:.c=.o}
PLUG_EXE		:= plugin-main

DREW_SONAME		:= libdrew.so.0
DREW_SYMLINK	:= ${DREW_SONAME:C/.so.*$/.so/}

RM				?= rm

CPPFLAGS		+= -Iinclude
CFLAGS			+= -Wall -fPIC -O6 -march=native -mtune=native -g
# One or more of the following options gives a slight speed improvement on MD2.
CFLAGS			+= -fgcse-sm -fgcse-las -ftree-loop-im
CFLAGS			+= -ftree-loop-ivcanon -fivopts -ftree-vectorize
CFLAGS			+= -ftracer
CFLAGS			+= ${CFLAGS-y} ${CPPFLAGS}
CXXFLAGS		+= ${CFLAGS}

LIBCFLAGS		+= -shared
PLUGINCFLAGS	+= -Iimpl/hash -I. ${LIBCFLAGS}

LIBS			+= -lrt -ldl

all: ${PLUG_EXE} ${DREW_SONAME}

.include "impl/hash/Makefile"
.include "libmd/Makefile"

standard: ${DREW_SONAME} ${MD_SONAME} plugins testsuite test/test-hash

${DREW_SONAME}: plugin.c
	${CC} ${CFLAGS} ${LIBCFLAGS} -shared -o ${.TARGET} ${.ALLSRC} ${LIBS}

${DREW_SYMLINK}: ${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}

${TEST_EXE}: ${TEST_SRC} ${MD_SONAME} ${DREW_SONAME}
	${CC} -Ilibmd/include ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${PLUG_EXE}: ${PLUG_OBJ} ${DREW_SONAME}
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

.c.o:
	${CC} ${CFLAGS} -c -o ${.TARGET} ${.IMPSRC}

.cc.o:
	${CXX} ${CXXFLAGS} -c -o ${.TARGET} ${.IMPSRC}

.for i in ${PLUGINS}
$i: $i.cc
	${CXX} ${PLUGINCFLAGS} ${CFLAGS} -o ${.TARGET} ${.ALLSRC}
.endfor

test/test-hash: test/test-hash.o ${DREW_SONAME} 
	${CC} ${CFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

plugins: ${PLUGINS}
	[ -d plugins ] || mkdir plugins
	cp ${.ALLSRC} plugins

clean:
	${RM} -f *.o
	${RM} -f ${TEST_EXE}
	${RM} -f ${PLUG_EXE}
	${RM} -f ${MD_SONAME} ${MD_OBJS}
	${RM} -f ${DREW_SONAME} ${DREW_SYMLINK}
	${RM} -fr ${PLUGINS} plugins/

test: ${TEST_EXE}
	env LD_LIBRARY_PATH=. ./${TEST_EXE} -x | \
		grep -v 'bytes in' | diff -u test-results -
