ifeq ($(CFG_DCT_XSLT),y)
FO_SHEETDIR		:= $(HOME)/.crustytoothpaste/groups/xsl-sheets/docbook/fo
XHTML_SHEETDIR	:= $(HOME)/.crustytoothpaste/groups/xsl-sheets/docbook/xhtml5

FO_STYLE		:= base
XHTML_STYLE		:= base

FO_SSHEET		:= $(FO_SHEETDIR)/style/$(FO_STYLE)/cvt.xsl
FO_PSTP			:= $(FO_SHEETDIR)/style/$(FO_STYLE)/pstp.xsl

XHTML_SSHEET	:= $(XHTML_SHEETDIR)/style/$(XHTML_STYLE)/cvt.xsl
XHTML_PSTP		:= $(XHTML_SHEETDIR)/style/$(XHTML_STYLE)/pstp.xsl
else
FO_SHEETDIR		:= /usr/share/xml/docbook/stylesheet/docbook-xsl-ns/fo
XHTML_SHEETDIR	:= /usr/share/xml/docbook/stylesheet/docbook-xsl-ns/xhtml

FO_SSHEET		:= $(FO_SHEETDIR)/docbook.xsl
XHTML_SSHEET	:= $(XHTML_SHEETDIR)/docbook.xsl
endif

FOP			?= fop
FOP_CFG_FILE:= /etc/fop/fop.xconf
FOP_CONFIG	:= $(shell test -f $(FOP_CFG_FILE) && echo "-c $(FOP_CFG_FILE)")

TSTROFF		?= tenorsax-troff
XSLTPROC	?= xsltproc

MANUAL_DIR	:= doc/manual

STYLEARGS	:= --param fop1.extensions 1
STYLEARGS	+= --param free.fonts.only 1
STYLEARGS	+= --stringparam funcsynopsis.style ansi

GEN_SUFFIXES	:= .pdf .ps .fo .txml .xhtml

.SUFFIXES: .xml .mx $(GEN_SUFFIXES)

doc: $(MANUAL_DIR)/drew.pdf
doc: $(MANUAL_DIR)/drew.ps
doc: $(MANUAL_DIR)/drew.xhtml

DREW_COMPONENTS	:= intro interface basics hash block stream libdrew

$(MANUAL_DIR)/drew.fo: $(patsubst %,$(MANUAL_DIR)/%.xml,$(DREW_COMPONENTS))

.fo.pdf:
	$(FOP) $(FOP_CONFIG) -fo $< -pdf $@

.fo.ps:
	$(FOP) $(FOP_CONFIG) -fo $< -ps $@

.mx.txml:
	$(TSTROFF) -mxd -Txml $(CUR) > $@

.xml.xhtml .txml.xhtml:
	$(XSLTPROC) --xinclude $(STYLEARGS) $(XHTML_SSHEET) $< | \
		(if [ -n "$(XHTML_PSTP)" ]; then \
			$(XSLTPROC) -o $@ $(XHTML_PSTP) -; \
			else \
			cat > $@; \
			fi)

.xml.fo .txml.fo:
	$(XSLTPROC) --xinclude $(STYLEARGS) $(FO_SSHEET) $< | \
		(if [ -n "$(FO_PSTP)" ]; then \
			$(XSLTPROC) -o $@ $(FO_PSTP) -; \
			else \
			cat > $@; \
			fi)

clean-doc:
	for i in $(GEN_SUFFIXES); do find -name "*$$i" | xargs rm -f; done
