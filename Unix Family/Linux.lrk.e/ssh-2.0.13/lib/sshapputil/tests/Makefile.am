## Process this file with automake to produce Makefile.in

#
# lib/sshutil/tests Makefile.am
#
# Author: Timo J. Rinne <tri@ssh.fi>
#
# Copyright (c) 1998 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

TESTS = t-userfile 

EXTRA_PROGRAMS = t-userfile

LDADD = ../libsshapputil.a \
	../../sshutil/libsshutil.a \
	../../sshmath/libsshmath.a

INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/.. \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I../../sshutil -I$(srcdir)/../../sshutil \
	   -I../../sshmath -I$(srcdir)/../../sshmath

t_userfile_SOURCES = t-userfile.c
t_userfile_DEPENDENCIES = $(LDADD)
