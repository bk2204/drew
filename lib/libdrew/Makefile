DREW_DIR		:= lib/libdrew
DREW_SONAME		:= libdrew.so.0
DREW_SYMLINK	:= $(basename $(DREW_SONAME))

ifneq ($(CFG_NEW_DREW),y)
CFG_OLD_DREW				:= y
endif

DREW_OBJS-$(CFG_OLD_DREW)	+= $(DREW_DIR)/plugin.o
DREW_OBJS-$(CFG_NEW_DREW)	+= $(DREW_DIR)/drew.o

${DREW_DIR}/${DREW_SONAME}: $(DREW_OBJS-y)
	${CC} ${CFLAGS} ${LIBCFLAGS} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${DREW_SONAME}: ${DREW_DIR}/${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}

${DREW_SYMLINK}: ${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}
