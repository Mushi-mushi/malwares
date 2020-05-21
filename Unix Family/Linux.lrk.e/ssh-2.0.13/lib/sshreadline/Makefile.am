## Process this file with automake to produce Makefile.in

#
# lib/sshreadline Makefile.am
#
# Author: Tero Kivinen <kivinen@ssh.fi>
#
# Copyright (c) 1997 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshreadline.a

libsshreadline_a_SOURCES = sshreadline.c
list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshreadline_a_OBJECTS) $(libsshreadline_a_LIBADD) :END_FILE_LIST

include_HEADERS = sshreadline.h
# noinst_HEADERS = 

INCLUDES = -I$(srcdir) -I. -I../.. \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../sshmath -I$(srcdir)/../sshmath \
	-I../zlib -I$(srcdir)/../zlib \
	-I../sshutil -I$(srcdir)/../sshutil

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file; \
	done
