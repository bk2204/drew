PLUGINS_PRNG-${CFG_ARC4STIR}		+= arc4/arc4stir
PLUGINS_PRNG-${CFG_ARC4IL}			+= arc4/arc4interleave
PLUGINS_PRNG-${CFG_SP80090}			+= sp800-90/sp800-90
PLUGINS_PRNG-${CFG_SYSPRNG}			+= system/sysprng

PRNG_DIR		:= impl/prng
PRNG_PLUGINS	:= $(patsubst %,${PRNG_DIR}/%,$(PLUGINS_PRNG-m))
PRNG_MODULES	+= $(patsubst %,${PRNG_DIR}/%.o,$(PLUGINS_PRNG-y))
PLUGINS			+= $(PRNG_PLUGINS)
MODULES			+= $(PRNG_MODULES)

${PRNG_DIR}/arc4/arc4stir.so:		${PRNG_DIR}/arc4/keystream.o
${PRNG_DIR}/arc4/arc4interleave.so:	${PRNG_DIR}/arc4/keystream.o

EXTRA_OBJECTS-${CFG_ARC4STIR}		+= ${PRNG_DIR}/arc4/keystream.o
EXTRA_OBJECTS-${CFG_ARC4IL}			+= ${PRNG_DIR}/arc4/keystream.o

$(EXTRA_OBJECTS-y): CPPFLAGS += -I$(PRNG_DIR) -DDREW_AS_MODULE
$(PRNG_PLUGINS): CPPFLAGS += -I$(PRNG_DIR) -DDREW_AS_PLUGIN
$(PRNG_MODULES): CPPFLAGS += -I$(PRNG_DIR) -DDREW_AS_MODULE
