## Process this file with automake to produce Makefile.in

#
# lib/sshapputil Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
# Copyright (c) 1998 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshapputil.a

libsshapputil_a_SOURCES = sshuserfile.c sshuserfilebuf.c 
list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshapputil_a_OBJECTS) $(libsshapputil_a_LIBADD) :END_FILE_LIST

include_HEADERS = sshuserfile.h \
		  sshuserfilebuf.h

INCLUDES = -I../.. -I. -I$(srcdir) \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../sshutil -I$(srcdir)/../sshutil -I../sshmath \
	-I$(srcdir)/../sshmath -I../zlib -I$(srcdir)/../zlib

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
