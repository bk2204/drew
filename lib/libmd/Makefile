MD_DIR					:= lib/libmd
MD_OBJS					:= $(MD_DIR)/impl.o
MD_SHOBJ-$(CFG_LIBMD)	:= libmd.so.0
MD_SONAME				:= ${MD_SHOBJ-y}

libmd: $(MD_DIR)/$(MD_SONAME)

$(MD_DIR)/$(MD_SONAME): $(MD_OBJS) | $(DREW_SONAME) $(DREW_IMPL_SONAME)
	$(CC) $(CFLAGS) $(LIBCFLAGS) $(SONAME) -o $@ $^ $|

$(MD_SONAME): | $(MD_DIR)/$(MD_SONAME)
	[ -L $@ ] || ln -sf $| $@

.PHONY: libmd
