# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.1l from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

# Generate this list with
# find . -type f -name '*.m4' -printf '%f\n'|sort |fmt |tr '\012' @ \
#   |sed 's/@$/%/;s/@/ \\@/g' |tr @% '\012\012'


SHELL = /bin/sh

srcdir = .
top_srcdir = ..
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

top_builddir = ..

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,
YACC = bison -y
RANLIB = ranlib
GENCAT = 
PERL = /usr/bin/perl
GMSGFMT = /usr/local/bin/msgfmt
CC = gcc

EXTRA_DIST = README \
ccstdc.m4 dmalloc.m4 error.m4 getgroups.m4 getline.m4 getloadavg.m4 \
gettext.m4 header.m4 init.m4 install.m4 jm-mktime.m4 jm-winsz1.m4 \
jm-winsz2.m4 lcmessage.m4 lispdir.m4 maintainer.m4 memcmp.m4 mktime.m4 \
obstack.m4 progtest.m4 protos.m4 ptrdiff.m4 regex.m4 sanity.m4 strftime.m4 \
strtod.m4 termios.m4 uptime.m4 winsz.m4
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../config.h
CONFIG_CLEAN_FILES = 
DIST_COMMON =  README Makefile.am Makefile.in README


PACKAGE = sh-utils
VERSION = 1.16

DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) \
	$(TEXINFOS) $(MANS) $(EXTRA_DIST)

TAR = tar
default: all

.SUFFIXES:
$(srcdir)/Makefile.in: #M# Makefile.am $(top_srcdir)/configure.in $(ACLOCAL) 
	cd $(top_srcdir) && automake --gnits m4/Makefile

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status $(BUILT_SOURCES)
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

tags: TAGS
TAGS:


distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)

subdir = m4
distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  test -f $(distdir)/$$file \
	  || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $$d/$$file $(distdir)/$$file; \
	done
info:
dvi:
check: all
	$(MAKE)
installcheck:
install-exec: 
	$(NORMAL_INSTALL)

install-data: 
	$(NORMAL_INSTALL)

install: install-exec install-data all
	@:

uninstall: 

all: Makefile

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

.PHONY: default tags distdir info dvi installcheck install-exec \
install-data install uninstall all installdirs mostlyclean-generic \
distclean-generic clean-generic maintainer-clean-generic clean \
mostlyclean distclean maintainer-clean


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
