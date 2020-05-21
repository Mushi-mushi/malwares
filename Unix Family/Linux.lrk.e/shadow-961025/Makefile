# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.0 from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.


SHELL = /bin/sh

srcdir = .
top_srcdir = .
prefix = /usr
exec_prefix = 

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

pkgdatadir = $(datadir)/shadow
pkglibdir = $(libdir)/shadow
pkgincludedir = $(includedir)/shadow

top_builddir = .

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = @INSTALL_SCRIPT@
transform = s,x,x,

AUTOMAKE_OPTIONS = 1.0 foreign

SUBDIRS = lib libmisc src \
# contrib doc etc old shlib
ACLOCAL = aclocal.m4
ACCONFIG = acconfig.h
CONFIG_HEADER_IN = config.h.in
mkinstalldirs = $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ./config.h

PACKAGE = shadow
VERSION = 961025

DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFOS) $(MANS) $(EXTRA_DIST) $(DATA)
DEP_DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFO_DEPS) $(MANS) $(EXTRA_DIST) $(DATA)

TAR = tar
default: all

# This directory's subdirectories are mostly independent; you can cd
# into them and run `make' without going through this Makefile.
# To change the values of `make' variables: instead of editing Makefiles,
# (1) if the variable is set in `config.status', edit `config.status'
#     (which will cause the Makefiles to be regenerated when you run `make');
# (2) otherwise, pass the desired values on the `make' command line.



all-recursive install-data-recursive install-exec-recursive \
installdirs-recursive install-recursive uninstall-recursive \
check-recursive installcheck-recursive info-recursive dvi-recursive \
mostlyclean-recursive clean-recursive distclean-recursive \
maintainer-clean-recursive:
	for subdir in $(SUBDIRS); do		\
	  target=`echo $@ | sed s/-recursive//`; \
	  echo making $$target in $$subdir;	\
	  (cd $$subdir && $(MAKE) $$target)	\
	   || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

tags: TAGS

tags-recursive:
	list="$(SUBDIRS)"; for subdir in $$list; do \
	  (cd $$subdir && $(MAKE) tags); \
	done

TAGS: tags-recursive $(HEADERS) $(SOURCES) $(CONFIG_HEADER) \
		$(TAGS_DEPENDENCIES)
	tags=; \
	here=`pwd`; \
	for subdir in $(SUBDIRS); do \
	  test -f $$subdir/TAGS && { \
	    tags="$$tags -i $$here/$$subdir/TAGS"; \
	  } \
	done; \
	test -z "$(ETAGS_ARGS)$(CONFIG_HEADER)$(SOURCES)$(HEADERS)$$tags" \
	  || etags $(ETAGS_ARGS) $$tags $(CONFIG_HEADER) $(SOURCES) $(HEADERS)

mostlyclean-tags:

clean-tags:

distclean-tags:
	rm -f TAGS ID

maintainer-clean-tags:

distdir = $(PACKAGE)-$(VERSION)
# This target untars the dist file and tries a VPATH configuration.  Then
# it guarantees that the distribution is self-contained by making another
# tarfile.
distcheck: dist
	rm -rf $(distdir)
	$(TAR) zxf $(distdir).tar.gz
	mkdir $(distdir)/=build
	mkdir $(distdir)/=inst
	dc_install_base=`cd $(distdir)/=inst && pwd`; \
	cd $(distdir)/=build \
	  && ../configure --srcdir=.. --prefix=$$dc_install_base \
	  && $(MAKE) \
	  && $(MAKE) check \
	  && $(MAKE) install \
	  && $(MAKE) installcheck \
	  && $(MAKE) dist
	rm -rf $(distdir)
	@echo "========================"; \
	echo "$(distdir).tar.gz is ready for distribution"; \
	echo "========================"
dist: distdir
	chmod -R a+r $(distdir)
	$(TAR) chozf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)
distdir: $(DEP_DISTFILES)
	rm -rf $(distdir)
	mkdir $(distdir)
	chmod 777 $(distdir)
	@for file in `cd $(srcdir) && echo $(DISTFILES)`; do \
	  test -f $(distdir)/$$file \
	  || ln $(srcdir)/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $(srcdir)/$$file $(distdir)/$$file; \
	done
	for subdir in $(SUBDIRS); do		\
	  test -d $(distdir)/$$subdir		\
	  || mkdir $(distdir)/$$subdir		\
	  || exit 1;				\
	  chmod 777 $(distdir)/$$subdir;	\
	  (cd $$subdir && $(MAKE) distdir=../$(distdir)/$$subdir distdir) \
	    || exit 1; \
	done
info: info-recursive

dvi: dvi-recursive

check: check-recursive

installcheck: installcheck-recursive

all-recursive-hack: $(CONFIG_HEADER)
	$(MAKE) all-recursive

all-am: Makefile config.h

install-exec: install-exec-recursive

install-data: install-data-recursive

install: install-recursive
	@:

uninstall: uninstall-recursive

all: all-recursive-hack all-am

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install
installdirs: installdirs-recursive


mostlyclean-generic:
	test -z "$(MOSTLYCLEANFILES)" || rm -f $(MOSTLYCLEANFILES)

clean-generic:
	test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	rm -f Makefile $(DISTCLEANFILES)
	rm -f config.cache config.log $(CONFIG_HEADER) stamp-h

maintainer-clean-generic:
	test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
	test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
mostlyclean-am:  mostlyclean-tags mostlyclean-generic

clean-am:  clean-tags clean-generic mostlyclean-am 

distclean-am:  distclean-tags distclean-generic clean-am 

maintainer-clean-am:  maintainer-clean-tags maintainer-clean-generic \
		distclean-am 

mostlyclean:  mostlyclean-am mostlyclean-recursive

clean:  clean-am clean-recursive

distclean:  distclean-am distclean-recursive
	rm -f config.status

maintainer-clean:  maintainer-clean-am maintainer-clean-recursive
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."
	rm -f config.status

.PHONY: default install-data-recursive uninstall-data-recursive \
install-exec-recursive uninstall-exec-recursive installdirs-recursive \
uninstalldirs-recursive all-recursive check-recursive \
installcheck-recursive info-recursive dvi-recursive \
mostlyclean-recursive distclean-recursive clean-recursive \
maintainer-clean-recursive tags tags-recursive mostlyclean-tags \
distclean-tags clean-tags maintainer-clean-tags distdir info dvi check \
installcheck all-recursive-hack all-am install-exec install-data \
install uninstall all installdirs mostlyclean-generic distclean-generic \
clean-generic maintainer-clean-generic clean mostlyclean distclean \
maintainer-clean

.SUFFIXES:

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
