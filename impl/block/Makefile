BLOCK_DIR						:= impl/block

PLUGINS_BLOCK-${CFG_CAST5}		+= cast/cast5
PLUGINS_BLOCK-${CFG_CAST6}		+= cast/cast6
PLUGINS_BLOCK-${CFG_BLOWFISH}	+= blowfish/blowfish
PLUGINS_BLOCK-${CFG_AESNI}		+= aes-native/aesni
PLUGINS_BLOCK-${CFG_AES}		+= aes/aes
PLUGINS_BLOCK-${CFG_RIJNDAEL}	+= rijndael/rijndael
PLUGINS_BLOCK-${CFG_TWOFISH}	+= twofish/twofish
PLUGINS_BLOCK-${CFG_DES}		+= des/des
PLUGINS_BLOCK-${CFG_CAMELLIA}	+= camellia/camellia
PLUGINS_BLOCK-${CFG_RC2}		+= rc2/rc2
PLUGINS_BLOCK-${CFG_SERPENT}	+= serpent/serpent
PLUGINS_BLOCK-${CFG_TEA}		+= tea/tea
PLUGINS_BLOCK-${CFG_XTEA}		+= xtea/xtea
PLUGINS_BLOCK-${CFG_SEED}		+= seed/seed
PLUGINS_BLOCK-${CFG_IDEA}		+= idea/idea
PLUGINS_BLOCK-${CFG_ARIA128}	+= aria/aria128
PLUGINS_BLOCK-${CFG_ARIABYTE}	+= aria/ariabyte
PLUGINS_BLOCK-${CFG_SHACAL}		+= shacal/shacal
PLUGINS_BLOCK-${CFG_LINUXBLOCK}	+= linux/linuxblock

${BLOCK_DIR}/cast/cast5.so: ${BLOCK_DIR}/cast/sboxes.o
${BLOCK_DIR}/cast/cast6.so: ${BLOCK_DIR}/cast/sboxes.o
${BLOCK_DIR}/aria/aria128.so:	${BLOCK_DIR}/aria/aria.o
${BLOCK_DIR}/aria/ariabyte.so:	${BLOCK_DIR}/aria/aria.o
${BLOCK_DIR}/serpent/serpent.so:	${BLOCK_DIR}/serpent/serpent-impl.o

EXTRA_OBJECTS-${CFG_CAST5}		+= ${BLOCK_DIR}/cast/sboxes.o
EXTRA_OBJECTS-${CFG_CAST6}		+= ${BLOCK_DIR}/cast/sboxes.o
EXTRA_OBJECTS-${CFG_ARIA128}	+= ${BLOCK_DIR}/aria/aria.o
EXTRA_OBJECTS-${CFG_ARIABYTE}	+= ${BLOCK_DIR}/aria/aria.o
EXTRA_OBJECTS-${CFG_SERPENT}	+= ${BLOCK_DIR}/serpent/serpent-impl.o

${BLOCK_DIR}/shacal/shacal.so:	${HASH_DIR}/sha1/sha1.o
${BLOCK_DIR}/linux/linuxblock.so:	impl/multi/linux/af-alg.o

EXTRA_OBJECTS-${CFG_SHACAL}		+= ${HASH_DIR}/sha1/sha1.o
EXTRA_OBJECTS-${CFG_LINUXBLOCK}	+= impl/multi/linux/af-alg.o

${BLOCK_DIR}/shacal/shacal.o: CPPFLAGS += -I${HASH_DIR}
${BLOCK_DIR}/shacal/shacal.d: CPPFLAGS += -I${HASH_DIR}

BLOCK_PLUGINS	:= $(patsubst %,${BLOCK_DIR}/%,$(PLUGINS_BLOCK-m))
BLOCK_MODULES	:= $(patsubst %,${BLOCK_DIR}/%.o,$(PLUGINS_BLOCK-y))
PLUGINS			+= $(BLOCK_PLUGINS)
MODULES			+= $(BLOCK_MODULES)
OBJECTS			+= $(EXTRA_OBJECTS-y) $(EXTRA_OBJECTS-m)

$(EXTRA_OBJECTS-y):			CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_MODULE
$(EXTRA_OBJECTS-y:.o=.d):	CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_MODULE
$(BLOCK_PLUGINS):			CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_PLUGIN
$(BLOCK_MODULES):			CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_MODULE
$(BLOCK_PLUGINS:=.d):		CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_PLUGIN
$(BLOCK_MODULES:.o=.d):		CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_MODULE
