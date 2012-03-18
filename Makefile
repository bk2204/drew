include config

VERSION			:= $(shell test -d .git && git describe)

CATEGORIES		:= hash block mode mac stream prng bignum pkenc pksig kdf ecc

RM				?= rm
RMDIR			?= rmdir

INSTALL_PROG	?= install
INSTALL_OPTS	:= $(shell [ `id -u` -eq 0 ] && printf -- "-o root -g root\n" || printf "\n")
INSTALL			:= $(INSTALL_PROG) $(INSTALL_OPTS)

TEST_ARG		= $(shell $(CC) $(1) -x c -o /dev/null -c /dev/null 2>/dev/null && echo $(1))

ifdef PROF
CLIKEFLAGS		+= -pg
endif
ifeq ($(CFG_THREAD_SAFE),y)
CLIKEFLAGS		+= -D_REENTRANT -D_THREAD_SAFE
endif
ifeq ($(CFG_FORTIFY),y)
CLIKEFLAGS		+= -D_FORTIFY_SOURCE=2
endif
ifeq ($(CFG_STACK_CHECK),y)
CLIKEFLAGS		+= -fstack-protector
endif

CPPFLAGS		+= -Iinclude -I$(dir $@)
CLIKEFLAGS		+= -Wall -Werror -fPIC -O3 -g -pipe
CLIKEFLAGS		+= -D_POSIX_SOURCE=200112L -D_XOPEN_SOURCE=600
CLIKEFLAGS		+= -fextended-identifiers
CLIKEFLAGS		+= -floop-interchange -floop-block
CLIKEFLAGS		+= -fvisibility=hidden
CLIKEFLAGS		+= $(CFLAGS-y)
CXXFLAGS		:= $(CLIKEFLAGS)
CFLAGS			:= $(CLIKEFLAGS)
CXXFLAGS		+= -fno-rtti
CFLAGS			+= -std=c99

LIBCFLAGS		+= -shared
PLUGINCFLAGS	+= -I.

LDFLAGS			+= -Wl,--as-needed
LIBS			+= $(LDFLAGS) -lrt -ldl

SONAME			= -Wl,-soname,$(@F)

all:

include lib/libdrew/Makefile
include lib/libmd/Makefile
include $(patsubst %,impl/%/Makefile,$(CATEGORIES))
include lib/libdrew-impl/Makefile
include test/Makefile
include util/Makefile
include doc/manual/Makefile

IMPL_OBJS		:= $(PLUGINS:=.o) $(MODULES)
OBJECTS			+= $(IMPL_OBJS)
OBJECTS			+= $(EXTRA_OBJECTS-y) $(EXTRA_OBJECTS-m)

IMPL_DIRS		:= $(sort $(foreach obj,$(IMPL_OBJS),$(dir $(obj))))

DEPFILES		:= $(OBJECTS:.o=.d)

all: $(DREW_SONAME) standard

depend: $(DEPFILES)

standard: $(DREW_SONAME) $(MD_SONAME) symlinks plugins
standard: $(TEST_BINARIES) $(UTILITIES)

symlinks: $(DREW_LSYMLINK) $(DREW_IMPL_LSYMLINK)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.cc.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

%.d: %.c
	$(CC) $(CPPFLAGS) -DDEPEND -MM $< | sed -e 's,$(*F)\.o:,$*.o $@:,g' > $@
	(x="$@"; [ -n "$${x##impl/*}" ] || \
		printf "$*.o: $(@D)/metadata.gen\n" >> $@)

%.d: %.cc
	$(CC) $(CPPFLAGS) -DDEPEND -MM $< | sed -e 's,$(*F)\.o:,$*.o $@:,g' > $@
	(x="$@"; [ -n "$${x##impl/*}" ] || \
		printf "$*.o: $(@D)/metadata.gen\n" >> $@)

${PLUGINS:=.o}: CPPFLAGS += $(PLUGINCFLAGS)

$(PLUGINS): %: %.so
	@:

$(PLUGINS:=.so): %.so: %.o
	$(CXX) $(LIBCFLAGS) $(CXXFLAGS) -o $@ $^ $(LIBS)

version:
	printf '#define DREW_STRING_VERSION "$(VERSION)"\n' > $@
	printf '#define DREW_VERSION %s\n' \
		`echo $(VERSION) | perl -pe 's/v(\d+)(-.*)?/$$1/'` >> $@

buildid:
	echo $$(uuidgen || \
		(dd if=/dev/urandom bs=15c count=1 | base64) 2>/dev/null) | \
		tr '+/-' '___' > $@

include/buildid.h: buildid
	printf '#if 0\n%s\n#else\n' $$(cat buildid) > $@
	printf '#define DREW_BUILD_IMPL_SONAME "$(DREW_IMPL_SONAME)"\n' >> $@
	printf '#define DREW_BUILD_UUID "DREW_%s"\n' $$(cat buildid) >> $@
	printf '#endif\n' >> $@

%/metadata.gen:
ifeq ($(CFG_METADATA),y)
	tools/generate-metadata -v $(dir $@)/metadata.rdf
else
	touch $@
endif

.PHONY: version tags

include/version.h: version
	if ! cmp -s $@ $<; then mv $< $@; else $(RM) $<; fi

tags:
	$(RM) tags
	find -name '*.c' -o -name '*.cc' -o -name '*.h' -o -name '*.hh' | \
		xargs ctags -a

plugins: $(PLUGINS)
	[ -d plugins ] || mkdir plugins
	for i in $^; do cp $$i.so plugins/`basename $$i .so`; done

clean:
	$(RM) -f *.o test/*.o
	$(RM) -f $(MD_SONAME) $(MD_OBJS)
	$(RM) -f $(DREW_SONAME) $(DREW_SYMLINK)
	$(RM) -f $(TEST_BINARIES)
	$(RM) -f $(UTILITIES)
	$(RM) -f include/version.h include/buildid.h
	$(RM) -f buildid
	$(RM) -fr $(PLUGINS) plugins/
	$(RM) -r install
	$(RM) -f tags
	find -name '*.gen' | xargs -r rm
	find -name '*.o' | xargs -r rm
	find -name '*.d' | xargs -r rm
	find -name '*.so' | xargs -r rm
	find -name '*.so.*' | xargs -r rm
	find -name '*.pdf' | xargs -r rm
	find -name '*.fo' | xargs -r rm

test: .PHONY

test check: test-scripts testx-scripts test-libmd
speed speed-test: speed-scripts

test-libmd: $(TEST_BINARIES) plugins
	env LD_LIBRARY_PATH=. test/libmd-testsuite -x | \
		grep -v 'bytes in' | diff -u test/libmd-test-results -

test-scripts: $(TEST_BINARIES) plugins
	set -e; for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -i; \
		done

testx-scripts: $(TEST_BINARIES) plugins
	set -e; for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -t; \
		done

test-api: $(TEST_BINARIES) plugins
	for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -p; \
		done

speed-scripts: $(TEST_BINARIES) plugins
	for i in $(CATEGORIES); do \
		find plugins -type f | sed -e 's,.*/,,g' | \
		sort | grep -vE '.rdf$$' | \
		xargs env LD_LIBRARY_PATH=. test/test-$$i -s; \
		done

install: .PHONY

INSTDIR			:= $(CFG_INSTALL_DIR)

install: all
	$(INSTALL) -m 755 -d $(INSTDIR)/lib/drew/plugins
	$(INSTALL) -m 755 -d $(INSTDIR)/include
	find plugins -type f | \
		xargs -I%s $(INSTALL) -m 644 %s $(INSTDIR)/lib/drew/plugins
	$(INSTALL) -m 644 libdrew*.so.* $(INSTDIR)/lib
	[ "$(CFG_LIBMD)" != y ] ||  $(INSTALL) -m 644 $(MD_SONAME) $(INSTDIR)/lib
	for i in libdrew*.so.*; do \
		ln -sf $(INSTDIR)/lib/$$i $(INSTDIR)/lib/drew/plugins; done
	for i in include/*; do \
		[ -f $$i ] || $(INSTALL) -m 755 -d $(INSTDIR)/$$i; \
		[ -f $$i ] || $(INSTALL) -m 644 $$i/*.h $(INSTDIR)/$$i; \
		done
	$(INSTALL) -m 755 $(UTILITIES) $(INSTDIR)/bin

uninstall:
	$(RM) $(INSTDIR)/lib/libdrew*.so.*
	$(RM) $(INSTDIR)/lib/$(MD_SONAME)
	find plugins -type f | xargs -I%s $(RM) $(INSTDIR)/lib/drew/%s
	for i in libdrew*.so.*; do $(RM) $(INSTDIR)/lib/drew/plugins/$$i; done
	for i in include/*; do \
		[ -f $$i ] || \
			($(RM) $(INSTDIR)/$$i/*.h; $(RMDIR) $(INSTDIR)/$$i); \
		done
	$(RMDIR) $(INSTDIR)/lib/drew/plugins || true
	$(RMDIR) $(INSTDIR)/lib/drew || true
	for i in $(UTILITIES); do $(RM) $(INSTDIR)/bin/`basename $$i`; done

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPFILES)
endif
