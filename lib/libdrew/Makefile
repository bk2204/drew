DREW_DIR		:= lib/libdrew
DREW_SONAME		:= libdrew.so.0
DREW_SYMLINK	:= $(basename $(DREW_SONAME))

DREW_OBJS		:= $(DREW_DIR)/drew.o

${DREW_DIR}/${DREW_SONAME}: $(DREW_OBJS)
	${CC} ${CFLAGS} ${LIBCFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${DREW_SONAME}: ${DREW_DIR}/${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}

${DREW_SYMLINK}: ${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}
