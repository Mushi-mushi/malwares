## Process this file with automake to produce Makefile.in

#
# lib/sshpgp/tests Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
# Copyright (c) 1998 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

TESTS = t-s2k

EXTRA_PROGRAMS = t-s2k pgpfiledump pgpkeysearch

LDADD = ../libsshpgp.a \
	../../sshcrypt/libsshcrypt.a \
	../../sshmath/libsshmath.a \
	../../sshutil/libsshutil.a \
	../../zlib/libz.a ../../trq/libtrq.a

INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/..	\
	-I$(top_builddir) -I$(top_srcdir)		\
	-I../../sshutil -I$(srcdir)/../../sshutil 	\
	-I../../sshmath -I$(srcdir)/../../sshmath 	\
	-I../../sshcrypt -I$(srcdir)/../../sshcrypt 	\
	-I../../zlib -I$(srcdir)/../../zlib 		\
	-I../../trq -I$(srcdir)/../../trq 

t_s2k_SOURCES = t-s2k.c
t_s2k_DEPENDENCIES = $(LDADD)

