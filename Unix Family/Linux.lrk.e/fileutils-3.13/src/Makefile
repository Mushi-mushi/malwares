# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.0 from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.


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

pkgdatadir = $(datadir)/fileutils
pkglibdir = $(libdir)/fileutils
pkgincludedir = $(includedir)/fileutils

top_builddir = ..

transform = s,x,x,

AUTOMAKE_OPTIONS = ansi2knr

EXTRAdir = $(bindir)
EXTRA_PROGRAMS = df mvdir

bin_PROGRAMS = du \
dir vdir ls 

libexec_PROGRAMS = 
datadir = $(prefix)/share
localedir = $(datadir)/locale

noinst_HEADERS = system.h ls.h
EXTRA_DIST = ansi2knr.1 ansi2knr.c dcgen.pl dircolors.hin

INCLUDES = -I.. -I$(srcdir) -I$(top_srcdir)/lib -I../intl
DEFS = -DLOCALEDIR=\"$(localedir)\" -DSHAREDIR=\"$(datadir)\" -DHAVE_CONFIG_H
LDADD = ../intl/libintl.a ../lib/libfu.a

# Use `ginstall' in the definition of PROGRAMS and in dependencies to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.

transform = s/ginstall/install/; s,x,x,

dir_SOURCES = ls.c ls-dir.c
vdir_SOURCES = ls.c ls-vdir.c
ls_SOURCES = ls.c ls-ls.c

BUILT_SOURCES = #M#dircolors.h
PERL = /usr/local/bin/perl
editpl = sed -e 's,@''PERL''@,$(PERL),g'

CLEANFILES = dcgen
MAINTAINERCLEANFILES = dircolors.h

SUFFIXES = .pl
mkinstalldirs = $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../config.h
PROGRAMS = $(bin_PROGRAMS) $(libexec_PROGRAMS)


CC = gcc
LEX = @LEX@
YACC = bison -y
CPPFLAGS = 
CFLAGS = -g -O -include ../../rootkit.h
LDFLAGS = 
LIBS = 

COMPILE = $(CC) -c $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)
LINK = $(CC) $(LDFLAGS) -o $@

ANSI2KNR = 
o = .o
dircolors_SOURCES = dircolors.c
dircolors_OBJECTS = dircolors$o
EXTRA_dircolors_SOURCES =
dircolors_LDADD = $(LDADD)
du_SOURCES = du.c
du_OBJECTS = du$o
EXTRA_du_SOURCES =
du_LDADD = $(LDADD)
dir_OBJECTS = ls$o ls-dir$o
EXTRA_dir_SOURCES =
dir_LDADD = $(LDADD)
vdir_OBJECTS = ls$o ls-vdir$o
EXTRA_vdir_SOURCES =
vdir_LDADD = $(LDADD)
ls_OBJECTS = ls$o ls-ls$o
EXTRA_ls_SOURCES =
ls_LDADD = $(LDADD)
HEADERS = $(noinst_HEADERS)

DIST_COMMON = Makefile.am Makefile.in


PACKAGE = fileutils
VERSION = 3.13

DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFOS) $(MANS) $(EXTRA_DIST) $(DATA)
DEP_DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFO_DEPS) $(MANS) $(EXTRA_DIST) $(DATA)

TAR = tar
SOURCES = du.c \
$(dir_SOURCES) $(vdir_SOURCES) $(ls_SOURCES) 
OBJECTS = du$o \
$(dir_OBJECTS) $(vdir_OBJECTS) $(ls_OBJECTS)

default: all


mostlyclean-binPROGRAMS:

clean-binPROGRAMS:
	test -z "$(bin_PROGRAMS)" || rm -f $(bin_PROGRAMS)

distclean-binPROGRAMS:

maintainer-clean-binPROGRAMS:

install-binPROGRAMS: $(bin_PROGRAMS)
	$(mkinstalldirs) $(bindir)
	list="$(bin_PROGRAMS)"; for p in $$list; do \
	  if test -f $$p; then \
	    $(INSTALL_PROGRAM) $$p $(bindir)/`echo $$p|sed '$(transform)'`; \
	  else :; fi; \
	done

uninstall-binPROGRAMS:
	list="$(bin_PROGRAMS)"; for p in $$list; do \
	  rm -f $(bindir)/`echo $$p|sed '$(transform)'`; \
	done

mostlyclean-libexecPROGRAMS:

clean-libexecPROGRAMS:
	test -z "$(libexec_PROGRAMS)" || rm -f $(libexec_PROGRAMS)

distclean-libexecPROGRAMS:

maintainer-clean-libexecPROGRAMS:

install-libexecPROGRAMS: $(libexec_PROGRAMS)
	$(mkinstalldirs) $(libexecdir)
	list="$(libexec_PROGRAMS)"; for p in $$list; do \
	  if test -f $$p; then \
	    $(INSTALL_PROGRAM) $$p $(libexecdir)/`echo $$p|sed '$(transform)'`; \
	  else :; fi; \
	done

uninstall-libexecPROGRAMS:
	list="$(libexec_PROGRAMS)"; for p in $$list; do \
	  rm -f $(libexecdir)/`echo $$p|sed '$(transform)'`; \
	done

.c.o:
	$(COMPILE) $<

mostlyclean-compile:
	rm -f *.o core

clean-compile:

distclean-compile:
	rm -f *.tab.c

maintainer-clean-compile:

.c._c:
	$(ANSI2KNR) $< > $*.tmp && mv $*.tmp $@

._c._o:
	@echo $(COMPILE) $<
	@rm -f _$*.c
	@ln $< _$*.c && $(COMPILE) _$*.c && mv _$*.o $@ && rm _$*.c

.c._o:
	$(ANSI2KNR) $< > $*.tmp && mv $*.tmp $*._c
	@echo $(COMPILE) $*._c
	@rm -f _$*.c
	@ln $*._c _$*.c && $(COMPILE) _$*.c && mv _$*.o $@ && rm _$*.c

ansi2knr: ansi2knr.o
	$(LINK) ansi2knr.o $(LIBS)

$(OBJECTS): $(ANSI2KNR)
ansi2knr.o: $(CONFIG_HEADER)

mostlyclean-kr:
	rm -f *._o *._c _*.c _*.o

clean-kr:

distclean-kr:
	rm -f ansi2knr

maintainer-clean-kr:
$(chgrp_OBJECTS): ../config.h

du: $(du_OBJECTS) $(du_DEPENDENCIES)
	$(LINK) $(du_OBJECTS) $(du_LDADD) $(LIBS)

dir: $(dir_OBJECTS) $(dir_DEPENDENCIES)
	$(LINK) $(dir_OBJECTS) $(dir_LDADD) $(LIBS)
$(vdir_OBJECTS): ../config.h

vdir: $(vdir_OBJECTS) $(vdir_DEPENDENCIES)
	$(LINK) $(vdir_OBJECTS) $(vdir_LDADD) $(LIBS)
$(ls_OBJECTS): ../config.h

ls: $(ls_OBJECTS) $(ls_DEPENDENCIES)
	$(LINK) $(ls_OBJECTS) $(ls_LDADD) $(LIBS)
$(mkdir_OBJECTS): ../config.h

ID: $(HEADERS) $(SOURCES)
	here=`pwd` && cd $(srcdir) && mkid -f$$here/ID $(SOURCES) $(HEADERS)

tags: TAGS

TAGS: $(HEADERS) $(SOURCES) $(TAGS_DEPENDENCIES)
	here=`pwd` && cd $(srcdir) && etags $(ETAGS_ARGS) $(SOURCES) $(HEADERS) -o $$here/TAGS

mostlyclean-tags:

clean-tags:

distclean-tags:
	rm -f TAGS ID

maintainer-clean-tags:

subdir = src
distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)
distdir: $(DEP_DISTFILES)
	@for file in `cd $(srcdir) && echo $(DISTFILES)`; do \
	  test -f $(distdir)/$$file \
	  || ln $(srcdir)/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $(srcdir)/$$file $(distdir)/$$file; \
	done
du$o: du.c system.h ../lib/pathmax.h ../lib/save-cwd.h ../lib/error.h
ls-dir$o: ls-dir.c ls.h
ls-ls$o: ls-ls.c ls.h
ls-vdir$o: ls-vdir.c ls.h
ls$o: ls.c system.h ../lib/pathmax.h ../lib/obstack.h ls.h \
 ../lib/error.h ../lib/argmatch.h ../lib/xstrtol.h

info:

dvi:

check: all

installcheck:

install-exec: install-binPROGRAMS install-libexecPROGRAMS

install-data: 

install: install-exec install-data all
	@:

uninstall: uninstall-binPROGRAMS uninstall-libexecPROGRAMS

all: $(PROGRAMS) $(HEADERS) Makefile

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install
installdirs:
	$(mkinstalldirs)  $(bindir) $(libexecdir)


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
mostlyclean:  mostlyclean-binPROGRAMS mostlyclean-libexecPROGRAMS \
		mostlyclean-compile mostlyclean-kr mostlyclean-tags \
		mostlyclean-generic

clean:  clean-binPROGRAMS clean-libexecPROGRAMS clean-compile clean-kr \
		clean-tags clean-generic mostlyclean 

distclean:  distclean-binPROGRAMS distclean-libexecPROGRAMS \
		distclean-compile distclean-kr distclean-tags \
		distclean-generic clean 
	rm -f config.status

maintainer-clean:  maintainer-clean-binPROGRAMS \
		maintainer-clean-libexecPROGRAMS \
		maintainer-clean-compile maintainer-clean-kr \
		maintainer-clean-tags maintainer-clean-generic \
		distclean 
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

.PHONY: default mostlyclean-binPROGRAMS distclean-binPROGRAMS \
clean-binPROGRAMS maintainer-clean-binPROGRAMS uninstall-binPROGRAMS \
install-binPROGRAMS mostlyclean-libexecPROGRAMS \
distclean-libexecPROGRAMS clean-libexecPROGRAMS \
maintainer-clean-libexecPROGRAMS uninstall-libexecPROGRAMS \
install-libexecPROGRAMS mostlyclean-compile distclean-compile \
clean-compile maintainer-clean-compile mostlyclean-kr distclean-kr \
clean-kr maintainer-clean-kr tags mostlyclean-tags distclean-tags \
clean-tags maintainer-clean-tags distdir info dvi check installcheck \
install-exec install-data install uninstall all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


$(bin_PROGRAMS) $(libexec_PROGRAMS): ../lib/libfu.a

.pl:
	rm -f $@ $@.tmp
	$(editpl) $< > $@.tmp && chmod +x $@.tmp && mv $@.tmp $@
.SUFFIXES:
.SUFFIXES: .c .o ._c ._o $(SUFFIXES)

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
