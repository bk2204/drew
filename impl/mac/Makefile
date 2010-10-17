PLUGINS_MAC-${CFG_HMAC}		+= hmac/hmac

MAC_DIR			:= impl/mac
MAC_PLUGINS		:= $(patsubst %,${MAC_DIR}/%,$(PLUGINS_MAC-m))
PLUGINS			+= $(MAC_PLUGINS)

$(MAC_PLUGINS): CPPFLAGS += -I$(MAC_DIR)
