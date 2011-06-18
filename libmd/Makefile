#MD_OBJS					:= ${MD_SRC-y:O:u:.c=.o}
MD_OBJS					:= libmd/impl.o
MD_SHOBJ-${CFG_LIBMD}	:= libmd.so.0
MD_SONAME				:= ${MD_SHOBJ-y}

libmd: ${MD_SONAME}

${MD_SONAME}: ${MD_OBJS} ${DREW_SONAME} ${DREW_IMPL_SONAME}
	${CC} ${CFLAGS} ${LIBCFLAGS} -Wl,-h${.TARGET} -o ${.TARGET} ${.ALLSRC}

.PHONY: libmd
