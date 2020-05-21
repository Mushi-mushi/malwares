## Process this file with automake to produce Makefile.in

#
# lib/sshproto/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

#TESTS = t-tr t-cross t-userauth t-conn t-pubkeyencode ### XXX Fix these!
TESTS = t-cross t-pubkeyencode

EXTRA_PROGRAMS = t-tr t-cross t-userauth t-conn t-pubkeyencode

LDADD = ../libsshproto.a ../../sshcrypt/libsshcrypt.a ../../sshutil/libsshutil.a ../../sshmath/libsshmath.a ../../zlib/libz.a

INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/.. \
  -I$(top_builddir) -I$(top_srcdir) \
  -I../../sshmath \
  -I$(srcdir)/../../sshmath -I../../sshutil -I$(srcdir)/../../sshutil \
  -I../../sshcrypt -I$(srcdir)/../../sshcrypt -I../../zlib \
  -I$(srcdir)/../../zlib

t_tr_SOURCES = t-tr.c
t_tr_DEPENDENCIES = $(LDADD)

t_cross_SOURCES = t-cross.c
t_cross_DEPENDENCIES = $(LDADD)

t_userauth_SOURCES = t-userauth.c
t_userauth_DEPENDENCIES = $(LDADD)

t_conn_SOURCES = t-conn.c
t_conn_DEPENDENCIES = $(LDADD)

t_pubkeyencode_SOURCES = t-pubkeyencode.c
t_pubkeyencode_DEPENDENCIES = $(LDADD)

