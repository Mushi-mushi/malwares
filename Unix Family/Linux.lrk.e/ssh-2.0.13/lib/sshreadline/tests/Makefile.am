## Process this file with automake to produce Makefile.in

#
# lib/sshreadline/tests Makefile.am
#
# Author: Tero Kivinen <kivinen@ssh.fi>
#
# Copyright (c) 1997 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

EXTRA_PROGRAMS = t-readline

LDADD = ../libsshreadline.a ../../sshutil/libsshutil.a -ltermcap

INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/.. \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../../sshmath -I$(srcdir)/../../sshmath \
	-I../../sshutil -I$(srcdir)/../../sshutil

t_readline_SOURCES = t-readline.c
t_readline_DEPENDENCIES = $(LDADD)

