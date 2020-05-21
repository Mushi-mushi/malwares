## Process this file with automake to produce Makefile.in

#
# lib/sshproto Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshproto.a

libsshproto_a_SOURCES = sshtrans.c trcommon.c trkex.c sshcross.c \
	sshcrup.c sshcrdown.c sshauthc.c sshauths.c sshconn.c \
	sshcipherlist.c
list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshproto_a_OBJECTS) $(libsshproto_a_LIBADD) :END_FILE_LIST

include_HEADERS = sshtrans.h sshcross.h sshauth.h sshconn.h sshmsgs.h \
	          sshcipherlist.h

noinst_HEADERS = trcommon.h trkex.h

# EXTRA_SOURCES = keydatab.c keydatab.h

INCLUDES = -I../.. -I. -I$(srcdir) \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../sshcrypt -I$(srcdir)/../sshcrypt \
	-I../sshutil -I$(srcdir)/../sshutil \
	-I../sshmath -I$(srcdir)/../sshmath

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done



