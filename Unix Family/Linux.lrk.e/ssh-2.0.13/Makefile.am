# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# top-level Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#         Timo J. Rinne <tri@ssh.fi>
#
# Copyright (c) 1996-1998 SSH Communications Security, Finland
#                         All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip

PACKAGE = ssh-src
VERSION = 0.0

SUBDIRS = lib apps

all-local: includes
includes:
	-if test '!' -d include; then mkdir include; fi
	$(COPY_INCLUDE) sshconf.h include
	$(COPY_INCLUDE) $(top_srcdir)/sshdistdefs.h include
	-for dir in $(SUBDIRS); do \
		( cd $$dir && $(MAKE) includes) ; \
	done

run_unit_tests_flags=--log-build --log-run --remove-and-make

unit-test:
	@if test -x $(top_srcdir)/test/run_unit_tests ; then             \
	    $(top_srcdir)/test/run_unit_tests $(run_unit_tests_flags) ;  \
	else                                                             \
	    echo No $(top_srcdir)/test/run_unit_tests available ;        \
	    false ;                                                      \
	fi

make-dist:
	$(srcdir)/autodist.pl --distributions $(srcdir)/distributions $(dist) $(srcdir)

dist-gmp:
	$(MAKE) make-dist dist=gmp

dist-ssh-commercial:
	$(MAKE) make-dist dist=ssh-commercial

dist-ssh-noncommercial:
	$(MAKE) make-dist dist=ssh-noncommercial

dist-ssh-internal:
	$(MAKE) make-dist dist=ssh-internal

dist-ssh-netload:
	$(MAKE) make-dist dist=ssh-netload

dist-ssh-aa:
	$(MAKE) make-dist dist=ssh-aa

dist-ipsec-100:
	$(MAKE) make-dist dist=ipsec

dist-ipsec-110:
	$(MAKE) make-dist dist=ipsec-110

dist-isakmp:
	$(MAKE) make-dist dist=isakmp

dist-ssh-emul:
	$(MAKE) make-dist dist=ssh-emul

dist-ssh-x509-library:
	$(MAKE) make-dist dist=x509-library


