# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypt Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshcrypt.a

libsshcrypt_a_SOURCES = \
  genhash.c \
  md5.c \
  sha.c \
  ripemd160.c \
  \
  genmac.c \
  hmac.c \
  macs.c \
  \
  genciph.c \
  nociph.c \
  des.c \
  blowfish.c \
  arcfour.c \
  twofish.c \
  \
  genpkcs.c \
  genmp.c \
  dlglue.c \
  dlfix.c \
  \
  \
  bufzip.c \
  \
  genaux.c \
  genrand.c \
  namelist.c \
  keyblob.c \
  ssh2pubkeyencode.c \
  libmonitor.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshcrypt_a_OBJECTS) $(libsshcrypt_a_LIBADD) :END_FILE_LIST

include_HEADERS = \
  sshcrypt.h \
  namelist.h \
  sshcrypti.h \
  sshrotate.h \
  sha.h \
  md5.h \
  ripemd160.h \
  des.h \
  blowfish.h \
  arcfour.h \
  twofish.h \
  hmac.h \
  macs.h \
  genmp.h \
  dlglue.h \
  dlfix.h \
  bufzip.h \
  keyblob.h \
  ssh2pubkeyencode.h \
  libmonitor.h


noinst_HEADERS = \
  nociph.h \
  timeit.h

libsshcrypt_a_LIBADD = @CRYPTO_CONF_OBJS@
libsshcrypt_a_DEPENDENCIES = @CRYPTO_CONF_OBJS@

EXTRA_DIST = \
  sshcrypt.h
# the sshcrypt.h above is a kludge; otherwise something handles the last
# backquote wrong

SUFFIXES = .S .s
CLEANFILES = tmp-*.s

LDADD = libsshcrypt.a \
	../sshutil/libsshutil.a ../sshmath/libsshmath.a

INCLUDES = -I../.. -I. -I$(srcdir) \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../sshutil -I$(srcdir)/../sshutil \
	-I../sshmath -I$(srcdir)/../sshmath \
	-I../zlib -I$(srcdir)/../zlib \
	-I../sshscard -I$(srcdir)/../sshscard \
	-I../trq -I$(srcdir)/../trq

.s.o:
	$(CC) -c $(CFLAGS) $(SFLAGS) $<

.S.o:
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	$(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	mv tmp-$*.o $@
	rm -f tmp-$*.s

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
