## Process this file with automake to produce Makefile.in

#
# lib/sshpgp Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
# Copyright (c) 1998 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

noinst_LIBRARIES = libsshpgp.a

libsshpgp_a_SOURCES = \
	pgp_gen.c \
	pgp_file.c \
	pgp_s2k.c \
	pgp_key.c \
	pgp_keydb.c \
	pgp_packet.c \
	pgp_cipher.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshpgp_a_OBJECTS) $(libsshpgp_a_LIBADD) :END_FILE_LIST
# libsshpgp_a_LIBADD = 
# libsshpgp_a_DEPENDENCIES = 

include_HEADERS = \
	sshpgp.h

INCLUDES = -I../.. -I. -I$(srcdir) 		\
	-I$(top_builddir) -I$(top_srcdir) 	\
	-I../sshutil -I$(srcdir)/../sshutil 	\
	-I../sshmath -I$(srcdir)/../sshmath 	\
	-I../sshcrypt -I$(srcdir)/../sshcrypt	\
	-I../zlib -I$(srcdir)/../zlib		\
	-I../trq -I$(srcdir)/../trq

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
