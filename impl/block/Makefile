PLUGINS_BLOCK-${CFG_CAST5}		+= cast/cast5
PLUGINS_BLOCK-${CFG_CAST6}		+= cast/cast6
PLUGINS_BLOCK-${CFG_BLOWFISH}	+= blowfish/blowfish
PLUGINS_BLOCK-${CFG_AES}		+= aes/aes
PLUGINS_BLOCK-${CFG_RIJNDAEL}	+= rijndael/rijndael
PLUGINS_BLOCK-${CFG_TWOFISH}	+= twofish/twofish
PLUGINS_BLOCK-${CFG_DES}		+= des/des
PLUGINS_BLOCK-${CFG_CAMELLIA}	+= camellia/camellia
PLUGINS_BLOCK-${CFG_RC2}		+= rc2/rc2

BLOCK_DIR		:= impl/block
BLOCK_PLUGINS	:= $(patsubst %,${BLOCK_DIR}/%,$(PLUGINS_BLOCK-m))
PLUGINS			+= $(BLOCK_PLUGINS)

$(BLOCK_PLUGINS): CPPFLAGS += -I$(BLOCK_DIR)
