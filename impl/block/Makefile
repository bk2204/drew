
BLOCK_DIR		:= impl/block
PLUGINS_BLOCK	:= cast5/cast5 blowfish/blowfish aes/aes rijndael/rijndael
PLUGINS_BLOCK	+= twofish/twofish des/des camellia/camellia

BLOCK_PLUGINS	:= $(patsubst %,${BLOCK_DIR}/%,$(PLUGINS_BLOCK))
PLUGINS			+= $(BLOCK_PLUGINS)

$(BLOCK_PLUGINS): CFLAGS += -I$(BLOCK_DIR)
$(BLOCK_PLUGINS): CXXFLAGS += -I$(BLOCK_DIR)
