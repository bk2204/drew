ifeq ($(CFG_DCT_XSLT),y)
SHEETDIR	:= $(HOME)/.crustytoothpaste/groups/xsl-sheets/docbook/fo

FO_STYLE	:= base

STYLE		:= $(SHEETDIR)/style/$(FO_STYLE)/cvt.xsl
PSTP		:= $(SHEETDIR)/style/$(FO_STYLE)/pstp.xsl
else
SHEETDIR	:= /usr/share/xml/docbook/stylesheet/docbook-xsl-ns/fo

STYLE		:= $(SHEETDIR)/docbook.xsl
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

GEN_SUFFIXES	:= .pdf .fo .txml

.SUFFIXES: .xml .mx $(GEN_SUFFIXES)

doc: $(MANUAL_DIR)/drew.pdf

DREW_COMPONENTS	:= intro interface basics hash block stream

$(MANUAL_DIR)/drew.fo: $(patsubst %,$(MANUAL_DIR)/%.xml,$(DREW_COMPONENTS))

.fo.pdf:
	$(FOP) $(FOP_CONFIG) -fo $< -pdf $@

.mx.txml:
	$(TSTROFF) -mxd -Txml $(CUR) > $@

.xml.fo .txml.fo:
	$(XSLTPROC) --xinclude $(STYLEARGS) $(STYLE) $< | \
		(if [ -n "$(PSTP)" ]; then \
			$(XSLTPROC) -o $@ $(PSTP) -; \
			else \
			cat > $@; \
			fi)

clean-doc:
	for i in $(GEN_SUFFIXES); do find -name "*$$i" | xargs rm -f; done
