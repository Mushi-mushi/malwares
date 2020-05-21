# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.1l from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.


SHELL = /bin/sh

srcdir = .
top_srcdir = ../..
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

pkgdatadir = $(datadir)/sh-utils
pkglibdir = $(libdir)/sh-utils
pkgincludedir = $(includedir)/sh-utils

top_builddir = ../..

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,
YACC = bison -y
RANLIB = ranlib
GENCAT = 
GMSGFMT = /usr/local/bin/msgfmt
CC = gcc

x = date
explicit =
maint_gen = t1.exp t2.exp t3.exp t4.exp t5.exp t6.exp t7.exp t8.exp t9.exp \
tleap-1.exp
run_gen = t1.out t1.err t2.out t2.err t3.out t3.err t4.out t4.err t5.out \
t5.err t6.out t6.err t7.out t7.err t8.out t8.err t9.out t9.err tleap-1.out \
tleap-1.err

EXTRA_DIST = mk-script.pl Test.pm $x-tests $(explicit) $(maint_gen)
noinst_SCRIPTS = $x-tests

PERL = /usr/bin/perl
editpl = sed -e 's,@''PERL''@,$(PERL),g' -e 's,@''srcdir''@,.,g'

TESTS = $x-tests

SUFFIXES = .pl

MAINTAINERCLEANFILES = $x-tests $(maint_gen)
CLEANFILES = $(run_gen)
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../../config.h
CONFIG_CLEAN_FILES = 
SCRIPTS =  $(noinst_SCRIPTS)

DIST_COMMON =  Makefile.am Makefile.in


PACKAGE = sh-utils
VERSION = 1.16

DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) \
	$(TEXINFOS) $(MANS) $(EXTRA_DIST)

TAR = tar
default: all

.SUFFIXES:
.SUFFIXES: .pl
$(srcdir)/Makefile.in: #M# Makefile.am $(top_srcdir)/configure.in $(ACLOCAL) 
	cd $(top_srcdir) && automake --gnits tests/date/Makefile

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status $(BUILT_SOURCES)
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

tags: TAGS
TAGS:


distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)

subdir = tests/date
distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  test -f $(distdir)/$$file \
	  || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $$d/$$file $(distdir)/$$file; \
	done
check-TESTS: $(TESTS)
	@failed=0; all=0; \
	srcdir=$(srcdir); export srcdir; \
	for tst in $(TESTS); do \
	  all=`expr $$all + 1`; \
	  if test -f $$tst; then dir=.; \
	  else dir="$(srcdir)"; fi; \
	  if $(TESTS_ENVIRONMENT) $$dir/$$tst; then \
	    echo "PASS: $$tst"; \
	  else \
	    failed=`expr $$failed + 1`; \
	    echo "FAIL: $$tst"; \
	  fi; \
	done; \
	if test "$$failed" -eq 0; then \
	  echo "========================"; \
	  echo "All $$all tests passed"; \
	  echo "========================"; \
	else \
	  echo "$$failed of $$all tests failed"; \
	fi
info:
dvi:
check: all
	$(MAKE) check-TESTS
installcheck:
install-exec: 
	$(NORMAL_INSTALL)

install-data: 
	$(NORMAL_INSTALL)

install: install-exec install-data all
	@:

uninstall: 

all: $(SCRIPTS) Makefile

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install
installdirs:


mostlyclean-generic:
	test -z "$(MOSTLYCLEANFILES)" || rm -f $(MOSTLYCLEANFILES)

clean-generic:
	test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	rm -f Makefile $(DISTCLEANFILES)
	rm -f config.cache config.log stamp-h
	test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)

maintainer-clean-generic:
	test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
	test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
mostlyclean:  mostlyclean-generic

clean:  clean-generic mostlyclean

distclean:  distclean-generic clean
	rm -f config.status

maintainer-clean:  maintainer-clean-generic distclean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

.PHONY: default tags distdir check-TESTS info dvi installcheck \
install-exec install-data install uninstall all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


$x-tests: #M#mk-script Test.pm
	./mk-script ../../src/$x > $@.n
	mv $@.n $@
	chmod 755 $@

.pl:
	rm -f $@ $@.tmp
	$(editpl) $< > $@.tmp
	chmod +x-w $@.tmp
	mv $@.tmp $@

#M#rebuild-check: Test.pm mk-script
#M#	rb=rb-check; rm -f $rb; \
#M#	m_template=../Makefile.am.in; \
#M#	sed -n '1,/^##test-files-begin/p' $$m_template > $$rb; \
#M#	tool=`echo $(subdir)|sed 's/^tests.//;s/-test//'`; \
#M#	echo "x = $$tool" >> $$rb; \
#M#	./mk-script --list >> $$rb; \
#M#	sed -n '/^##test-files-end/,$$p' $$m_template >> $$rb; \
#M#	diff -u Makefile.am $$rb && echo ok || echo no

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
