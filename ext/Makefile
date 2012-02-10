EXTENSIONS		:= perl

PERL_DIR		:= ext/perl/Digest-Drew

extensions: $(EXTENSIONS)

perl: buildid include/buildid.h
	(set -e; cd $(PERL_DIR) && perl Makefile.PL)
	(set -e; export DREW_$(shell cat buildid)=$$(pwd); \
		cd $(PERL_DIR) && $(MAKE) all test)

perl-clean:
	-(cd $(PERL_DIR) && $(MAKE) clean)
	$(RM) $(PERL_DIR)/Makefile.old

clean: perl-clean

.PHONY: perl
