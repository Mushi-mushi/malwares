# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshmath Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshmath.a 


libsshmath_a_SOURCES =	\
sshmp.c			\
sshmp-kernel.c		\
sieve.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshmath_a_OBJECTS) $(libsshmath_a_LIBADD) :END_FILE_LIST

include_HEADERS =	\
sshmp.h			\
sshmp-kernel.h			\
sieve.h			\
sshmath-types.h

noinst_HEADERS = 

libsshmath_a_LIBADD = @MATH_CONF_OBJS@
libsshmath_a_DEPENDENCIES = @MATH_CONF_OBJS@

EXTRA_DIST = \
  sshmp.h 

SUFFIXES = .S .s
CLEANFILES = tmp-*.s

LDADD = libsshmath.a
INCLUDES = -I../.. \
	-I$(top_builddir) -I$(top_srcdir) \
	-I. -I$(srcdir)  -I../sshutil/ \
	-I$(srcdir)/../sshutil

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
