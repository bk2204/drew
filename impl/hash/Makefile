PLUGINS_HASH-$(CFG_MD2)		+= md2/md2
PLUGINS_HASH-$(CFG_MD4)		+= md4/md4
PLUGINS_HASH-$(CFG_MD5)		+= md5/md5
PLUGINS_HASH-$(CFG_RIPE160)	+= ripe160/ripe160
PLUGINS_HASH-$(CFG_SHA1)	+= sha1/sha1
PLUGINS_HASH-$(CFG_SHA256)	+= sha256/sha256
PLUGINS_HASH-$(CFG_SHA512)	+= sha512/sha512
PLUGINS_HASH-$(CFG_TIGER)	+= tiger/tiger
PLUGINS_HASH-$(CFG_KECCAK)	+= keccak/keccak
PLUGINS_HASH-$(CFG_WHIRLPOOL)	+= whirlpool/whirlpool
PLUGINS_HASH-${CFG_GRØSTL}	+= grøstl/grøstl
PLUGINS_HASH-$(CFG_BLAKE)	+= blake/blake
PLUGINS_HASH-$(CFG_FUGUE)	+= fugue/fugue
PLUGINS_HASH-$(CFG_SKEIN)	+= skein/skein

HASH_DIR		:= impl/hash
HASH_PLUGINS	:= $(patsubst %,$(HASH_DIR)/%,$(PLUGINS_HASH-m))
HASH_MODULES	:= $(patsubst %,$(HASH_DIR)/%.o,$(PLUGINS_HASH-y))
PLUGINS			+= $(HASH_PLUGINS)
MODULES			+= $(HASH_MODULES)

BLOCK_DIR		?= impl/block

$(HASH_DIR)/skein/skein.so:	$(BLOCK_DIR)/threefish/threefish-impl.o

EXTRA_OBJECTS-$(CFG_SKEIN)	+= $(BLOCK_DIR)/threefish/threefish-impl.o

$(HASH_DIR)/skein/skein.o: CPPFLAGS += -I$(BLOCK_DIR)
$(HASH_DIR)/skein/skein.d: CPPFLAGS += -I$(BLOCK_DIR)

$(HASH_PLUGINS):		CPPFLAGS += -I$(HASH_DIR) -DDREW_AS_PLUGIN
$(HASH_MODULES):		CPPFLAGS += -I$(HASH_DIR) -DDREW_AS_MODULE
$(HASH_PLUGINS:=.d):	CPPFLAGS += -I$(HASH_DIR) -DDREW_AS_PLUGIN
$(HASH_MODULES:.o=.d):	CPPFLAGS += -I$(HASH_DIR) -DDREW_AS_MODULE
