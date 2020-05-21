# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshutil Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests
CONFOBJS = @LIBOBJS@

noinst_LIBRARIES = libsshutil.a

libsshutil_a_SOURCES = \
	sshbufaux.c		\
	sshbuffer.c		\
	sshfilebuffer.c		\
	sshunixeloop.c		\
	sshunixfdstream.c	\
	sshmiscstring.c		\
	sshmatch.c		\
	sshmpaux.c		\
	sshgetput.c		\
	sshtcp.c		\
	sshunixtcp.c		\
	sshstream.c		\
	sshdebug.c		\
	sshenum.c		\
	sshencode.c		\
	sshsocks.c		\
	sshunixlocalstream.c	\
	sshstreampair.c		\
	sshfilterstream.c	\
	sshbase64.c		\
	sshutf8.c		\
	sshfilexfer.c		\
	sshfilexferc.c		\
	sshfilexfers.c		\
	sshfilexferi.c		\
	sshunixrealpath.c	\
	sshsignals.c		\
	sshurl.c		\
	sshgetopt.c		\
	sshinet.c		\
	sshcstack.c		\
	sshvlint32.c		\
	sshcrc32.c		\
	sshfilelock.c		\
	sshfileio.c		\
	sshtimemeasure.c	\
	sshdllist.c		\
	sshmapping.c		\
	sshdsprintf.c		\
	sshtime.c		\
	sshaudit.c		\
	sshpacketwrapper.c	\
	sshpacketstream.c	\
	sshpacketimpl.c		\
	sshmalloc.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshutil_a_OBJECTS) $(libsshutil_a_LIBADD) :END_FILE_LIST
libsshutil_a_LIBADD = $(CONFOBJS)
libsshutil_a_DEPENDENCIES = $(CONFOBJS)

include_HEADERS = \
	sshincludes.h		\
	sshincludes_unix.h	\
	sshstream.h		\
	sshtimeouts.h		\
	sshsnprintf.h		\
	sshunixeloop.h		\
	sshgetput.h		\
	sshdebug.h		\
	sshbufaux.h		\
	sshbuffer.h		\
	sshfilebuffer.h		\
	sshenum.h		\
	sshencode.h		\
	sshunixfdstream.h	\
	sshmiscstring.h		\
	sshstreampair.h		\
	sshtcp.h		\
	sshsocks.h		\
	sshmatch.h		\
	sshmpaux.h		\
	sshfilterstream.h	\
	sshbase64.h		\
	sshutf8.h		\
	sshlocalstream.h	\
	sshfilexfer.h		\
	sshsignals.h		\
	sshurl.h		\
	sshgetopt.h		\
	sshinet.h		\
	sshcstack.h		\
	sshvlint32.h		\
	sshcrc32.h		\
	sshfilelock.h		\
	sshfileio.h		\
	sshtimemeasure.h	\
	sshdllist.h		\
	sshmapping.h		\
	sshdsprintf.h		\
	sshtime.h		\
	sshaudit.h		\
	sshpacketstream.h	\
	sshmalloc.h

noinst_HEADERS = sshpacketint.h sshfilexferi.h

EXTRA_DIST = \
	memmove.c memset.c putenv.c random.c remove.c snprintf.c \
	strcasecmp.c strerror.c strncasecmp.c getopt.c crypt.c \
	inet_ntoa.c

INCLUDES = -I. -I$(srcdir) -I.. -I$(srcdir)/..	\
	-I$(top_builddir) -I$(top_srcdir) 	\
	-I../sshmath -I$(srcdir)/../sshmath 	\
	-I../zlib -I$(srcdir)/../zlib 		\
	-I../trq -I$(srcdir)/../trq

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
