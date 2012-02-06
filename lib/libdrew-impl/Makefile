DREW_IMPL_DIR		:= lib/libdrew-impl
DREW_IMPL_SONAME	:= libdrew-impl.so.3
DREW_IMPL_SYMLINK	:= $(basename $(DREW_IMPL_SONAME))
DREW_IMPL_LSYMLINK	:= libdrew-impl.so
DREW_IMPL_GEN		:= $(DREW_IMPL_DIR)/modules.gen

$(DREW_IMPL_DIR)/stub.o: $(DREW_IMPL_DIR)/stub.c
$(DREW_IMPL_DIR)/stub.o: $(DREW_IMPL_GEN)

$(DREW_IMPL_DIR)/$(DREW_IMPL_SONAME): $(DREW_IMPL_DIR)/stub.o $(MODULES) $(EXTRA_OBJECTS-y)
	$(CXX) $(CXXFLAGS) $(LIBCFLAGS) $(SONAME) -o $@ $^ $(LIBS)

$(DREW_IMPL_SONAME): | $(DREW_IMPL_DIR)/$(DREW_IMPL_SONAME)
	[ -L $@ ] || ln -sf $| $@

$(DREW_IMPL_GEN): $(MODULES) config
	$(DREW_IMPL_DIR)/generate -m -o $(DREW_IMPL_GEN) $(patsubst %.o,%,$(MODULES))

$(DREW_IMPL_LSYMLINK): | $(DREW_IMPL_DIR)/$(DREW_IMPL_SONAME)
	[ -L $@ ] || ln -sf $| $@
