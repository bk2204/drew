BLOCK_DIR						:= impl/block

PLUGINS_BLOCK-${CFG_CAST5}		+= cast/cast5
PLUGINS_BLOCK-${CFG_CAST6}		+= cast/cast6
PLUGINS_BLOCK-${CFG_BLOWFISH}	+= blowfish/blowfish
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

${BLOCK_DIR}/cast/cast5-all.o: ${BLOCK_DIR}/cast/sboxes.o
${BLOCK_DIR}/cast/cast6-all.o: ${BLOCK_DIR}/cast/sboxes.o

EXTRA_OBJECTS-${CFG_CAST5}		+= ${BLOCK_DIR}/cast/sboxes.o
EXTRA_OBJECTS-${CFG_CAST6}		+= ${BLOCK_DIR}/cast/sboxes.o

BLOCK_PLUGINS	:= $(patsubst %,${BLOCK_DIR}/%,$(PLUGINS_BLOCK-m))
BLOCK_MODULES	:= $(patsubst %,${BLOCK_DIR}/%.o,$(PLUGINS_BLOCK-y))
PLUGINS			+= $(BLOCK_PLUGINS)
MODULES			+= $(BLOCK_MODULES)


$(BLOCK_PLUGINS): CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_PLUGIN
$(BLOCK_MODULES): CPPFLAGS += -I$(BLOCK_DIR) -DDREW_AS_MODULE
