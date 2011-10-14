DREW_DIR		:= lib/libdrew
DREW_SONAME		:= libdrew.so.0
DREW_SYMLINK	:= $(basename $(DREW_SONAME))

DREW_OBJS		:= $(DREW_DIR)/drew.o $(DREW_DIR)/mem.o
OBJECTS			+= $(DREW_OBJS)

DREW_CPPFLAGS	:= -DDREW_SEARCH_PATH='$(shell echo $(CFG_SEARCH_PATH) | perl -pe '$$_=join",",map{"\"$$_\""}split/\s+/;')'

$(DREW_SONAME): CPPFLAGS += $(DREW_CPPFLAGS)

${DREW_DIR}/${DREW_SONAME}: $(DREW_OBJS)
	${CC} ${CFLAGS} ${LIBCFLAGS} ${SONAME} -o ${.TARGET} ${.ALLSRC} ${LIBS}

${DREW_SONAME}: ${DREW_DIR}/${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}

${DREW_SYMLINK}: ${DREW_SONAME}
	ln -sf ${.ALLSRC} ${.TARGET}
