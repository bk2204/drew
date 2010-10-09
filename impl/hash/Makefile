
HASH_DIR		:= impl/hash
PLUGINS_HASH	:= md4/md4 md5/md5 ripe160/ripe160 sha1/sha1 sha256/sha256
PLUGINS_HASH	+= sha512/sha512 tiger/tiger
PLUGINS_HASH	+= md2/md2

HASH_PLUGINS	:= $(patsubst %,${HASH_DIR}/%,$(PLUGINS_HASH))
PLUGINS			+= $(HASH_PLUGINS)

$(HASH_PLUGINS): CFLAGS += -I$(HASH_DIR)
$(HASH_PLUGINS): CXXFLAGS += -I$(HASH_DIR)
