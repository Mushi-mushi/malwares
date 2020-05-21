# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.0 from Makefile.am

# Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.


SHELL = /bin/sh

srcdir = .
top_srcdir = ..
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

top_builddir = ..

INSTALL = /usr/bin/ginstall -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = @INSTALL_SCRIPT@
transform = s,x,x,

AUTOMAKE_OPTIONS = 1.0 foreign

# Watch out; note the difference between prefix & exec_prefix.
# Normally configure sets exec_prefix to root when prefix is /usr.

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
ubindir = ${prefix}/bin
usbindir = ${prefix}/sbin

bin_PROGRAMS = login

# id and groups are from gnu, the rest is perhaps not important
# also suid programs are installed by hand.

suidbins = su
suidubins = chage chfn chsh expiry gpasswd newgrp passwd

# login-static removed - too big and not really needed, it is better to
# upgrade your telnetd, the LD_xxx bug is sooo old...  --marekm

noinst_PROGRAMS = chfn chsh passwd 

LDADD=../libmisc/libmisc.a ../lib/libshadow.a
INCLUDES= -I$(top_srcdir)/lib

# These are to trick the linker to link only libcrypt statically

STATLINK = -Wl,-Bstatic
DYNLINK = -Wl,-Bdynamic

login_static_SOURCES = login.c

# Some tools need libcrypt.
chfn_LDADD = $(LDADD) 
chpasswd_LDADD = $(LDADD) 
chsh_LDADD = $(LDADD) 
dpasswd_LDADD = $(LDADD) 
gpasswd_LDADD = $(LDADD) 
login_LDADD = $(LDADD)  
login_static_LDADD = $(LDADD)   -static
newgrp_LDADD = $(LDADD) 
newusers_LDADD = $(LDADD) 
passwd_LDADD = $(LDADD)  
su_LDADD = $(LDADD)  
# I think it's better...
sulogin_LDADD = $(LDADD) $(STATLINK)  $(DYNLINK)
mkinstalldirs = $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../config.h
PROGRAMS = $(usbin_PROGRAMS) $(bin_PROGRAMS) $(noinst_PROGRAMS)


CC = gcc
LEX = @LEX@
YACC = @YACC@

DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I..
CPPFLAGS = 
CFLAGS = -O2 -Wall
LDFLAGS = -s
LIBS = 

COMPILE = $(CC) -c $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)
LINK = $(CC) $(LDFLAGS) -o $@
login_SOURCES = login.c
login_OBJECTS = login.o
EXTRA_login_SOURCES =
chfn_SOURCES = chfn.c
chfn_OBJECTS = chfn.o
EXTRA_chfn_SOURCES =
chsh_SOURCES = chsh.c
chsh_OBJECTS = chsh.o
EXTRA_chsh_SOURCES =
passwd_SOURCES = passwd.c
passwd_OBJECTS = passwd.o
EXTRA_passwd_SOURCES =
HEADERS = $(noinst_HEADERS)

DIST_COMMON = Makefile.am Makefile.in


PACKAGE = shadow
VERSION = 961025

DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFOS) $(MANS) $(EXTRA_DIST) $(DATA)
DEP_DISTFILES = $(DIST_COMMON) $(SOURCES) $(BUILT_SOURCES) $(HEADERS) \
	$(TEXINFOS) $(INFO_DEPS) $(MANS) $(EXTRA_DIST) $(DATA)

TAR = tar
SOURCES = login.c chfn.c chsh.c passwd.c
OBJECTS = login.o chfn.o chsh.o passwd.o

default: all


$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in
	cd $(top_srcdir) && automake $(subdir)/Makefile

mostlyclean-usbinPROGRAMS:

clean-usbinPROGRAMS:
	rm -f $(usbin_PROGRAMS)

clean-binPROGRAMS:
	rm -f $(bin_PROGRAMS)

clean-noinstPROGRAMS:
	rm -f $(noinst_PROGRAMS)

.c.o:
	$(COMPILE) $<

mostlyclean-compile:
	rm -f *.o core

clean-compile:

maintainer-clean-compile:
$(login_OBJECTS): ../config.h

login: $(login_OBJECTS) $(login_DEPENDENCIES)
	$(LINK) $(login_OBJECTS) $(login_LDADD) $(LIBS)
$(chfn_OBJECTS): ../config.h

chfn: $(chfn_OBJECTS) $(chfn_DEPENDENCIES)
	$(LINK) $(chfn_OBJECTS) $(chfn_LDADD) $(LIBS)
$(chsh_OBJECTS): ../config.h

chsh: $(chsh_OBJECTS) $(chsh_DEPENDENCIES)
	$(LINK) $(chsh_OBJECTS) $(chsh_LDADD) $(LIBS)
$(passwd_OBJECTS): ../config.h
passwd: $(passwd_OBJECTS) $(passwd_DEPENDENCIES)
	$(LINK) $(passwd_OBJECTS) $(passwd_LDADD) $(LIBS)

subdir = src
distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)
distdir: $(DEP_DISTFILES)
	@for file in `cd $(srcdir) && echo $(DISTFILES)`; do \
	  test -f $(distdir)/$$file \
	  || ln $(srcdir)/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $(srcdir)/$$file $(distdir)/$$file; \
	done
chfn.o: chfn.c ../lib/rcsid.h ../lib/prototypes.h ../lib/faillog.h \
 ../lib/defines.h ../lib/pwio.h ../lib/getdef.h ../lib/pwauth.h
chsh.o: chsh.c ../lib/rcsid.h ../lib/prototypes.h ../lib/faillog.h \
 ../lib/defines.h ../lib/pwio.h ../lib/getdef.h ../lib/pwauth.h
login.o: login.c ../lib/rcsid.h ../lib/prototypes.h ../lib/faillog.h \
 ../lib/defines.h ../lib/pwauth.h ../lib/getdef.h
passwd.o: passwd.c ../lib/rcsid.h ../lib/prototypes.h ../lib/faillog.h \
 ../lib/defines.h ../lib/pwauth.h ../lib/shadowio.h ../lib/pwio.h \
 ../lib/getdef.h

all: $(PROGRAMS) $(HEADERS) Makefile

distclean-generic:
	rm -f Makefile $(DISTCLEANFILES)
	rm -f config.cache config.log $(CONFIG_HEADER) stamp-h

mostlyclean:	mostlyclean-compile

clean:  clean-usbinPROGRAMS clean-binPROGRAMS clean-noinstPROGRAMS \
		clean-compile clean-tags clean-generic mostlyclean 

distclean:  distclean-usbinPROGRAMS distclean-binPROGRAMS \
		distclean-noinstPROGRAMS distclean-compile \
		distclean-tags distclean-generic clean 
	rm -f config.status

.PHONY: default mostlyclean-usbinPROGRAMS distclean-usbinPROGRAMS \
clean-usbinPROGRAMS maintainer-clean-usbinPROGRAMS \
uninstall-usbinPROGRAMS install-usbinPROGRAMS mostlyclean-binPROGRAMS \
distclean-binPROGRAMS clean-binPROGRAMS maintainer-clean-binPROGRAMS \
uninstall-binPROGRAMS install-binPROGRAMS mostlyclean-noinstPROGRAMS \
distclean-noinstPROGRAMS clean-noinstPROGRAMS \
maintainer-clean-noinstPROGRAMS mostlyclean-compile distclean-compile \
clean-compile maintainer-clean-compile tags mostlyclean-tags \
distclean-tags clean-tags maintainer-clean-tags distdir info dvi check \
installcheck install-exec install-data install uninstall all \
installdirs mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


install-exec-local:
	$(mkinstalldirs) $(bindir)
	for i in $(suidbins); do \
	  $(INSTALL) -m 4755 $$i $(bindir); \
	done
	$(mkinstalldirs) $(ubindir)
	for i in $(suidubins); do \
	  $(INSTALL) -m 4755 $$i $(ubindir); \
	done
	rm -f $(bindir)/sg
	ln -s $(ubindir)/newgrp $(bindir)/sg
.SUFFIXES:
.SUFFIXES: .c .o

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
