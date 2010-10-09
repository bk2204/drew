
BLOCK_DIR		:= impl/block
PLUGINS_BLOCK	:= cast5/cast5 blowfish/blowfish aes/aes rijndael/rijndael
PLUGINS_BLOCK	+= twofish/twofish des/des camellia/camellia

PLUGINS			+= $(patsubst %,${BLOCK_DIR}/%,$(PLUGINS_BLOCK))
