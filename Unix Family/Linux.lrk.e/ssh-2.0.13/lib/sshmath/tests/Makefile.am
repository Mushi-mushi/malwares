# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshmath/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

TESTS = t-mathtest \
t-mathspeed t-sophie-germain
# factor

EXTRA_PROGRAMS = t-mathtest t-test-ec t-mathspeed t-sophie-germain factor

EXTRA_DIST = 

noinst_HEADERS = timeit.h

LDADD = ../libsshmath.a ../../sshutil/libsshutil.a
INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/.. \
	-I$(top_builddir) -I$(top_srcdir) \
	-I../../sshmath \
	-I$(srcdir)/../../sshmath -I../../sshutil -I$(srcdir)/../../sshutil \
	-I../../zlib -I$(srcdir)/../../zlib

t_mathtest_SOURCES = t-mathtest.c
t_mathtest_DEPENDENCIES = $(LDADD)
t_mathspeed_SOURCES = t-mathspeed.c
t_mathspeed_DEPENDENCIES = $(LDADD)

t_sophie_germain_SOURCES = t-sophie-germain.c
t_sophie_germain_DEPENDENCIES = $(LDADD)
factor_SOURCES = factor.c
factor_DEPENDENCIES = $(LDADD)
