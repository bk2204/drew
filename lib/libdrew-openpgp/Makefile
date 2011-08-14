DREW_OPGP_DIR		:= lib/libdrew-openpgp
DREW_OPGP_SONAME	:= libdrew-openpgp.so.0
DREW_OPGP_SYMLINK	:= $(basename $(DREW_OPGP_SONAME))

DREW_OPGP_OBJS-y						+= parser.o
DREW_OPGP_OBJS-y						+= algo.o
DREW_OPGP_OBJS-y						+= key.o
DREW_OPGP_OBJS-y						+= sig.o
DREW_OPGP_OBJS-y						+= keystore.o
DREW_OPGP_OBJS-y						+= encrypt.o
DREW_OPGP_OBJS-$(CFG_OPGPBK_BDB)		+= keystore-bdb.o
DREW_OPGP_DIR_OBJS	+= $(patsubst %,$(DREW_OPGP_DIR)/%,$(DREW_OPGP_OBJS-y))

ifeq ($(CFG_OPGPBK_BDB),y)
$(DREW_OPGP_DIR_OBJS): CPPFLAGS += -DDREW_OPGP_BACKEND_BDB
endif

$(DREW_OPGP_DIR)/$(DREW_OPGP_SONAME): CFLAGS += -I$(DREW_OPGP_DIR)/include
$(DREW_OPGP_DIR)/$(DREW_OPGP_SONAME): $(DREW_OPGP_DIR_OBJS)
	$(CXX) $(CXXFLAGS) $(LIBCFLAGS) -o $(.TARGET) $(.ALLSRC) $(LIBS)

$(DREW_OPGP_SONAME): $(DREW_OPGP_DIR)/$(DREW_OPGP_SONAME)
	ln -sf $(.ALLSRC) $(.TARGET)

$(DREW_OPGP_SYMLINK): $(DREW_OPGP_SONAME)
	ln -sf $(.ALLSRC) $(.TARGET)
