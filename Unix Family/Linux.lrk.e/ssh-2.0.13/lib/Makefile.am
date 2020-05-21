# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = zlib sshmath sshreadline sshutil sshapputil sshcrypt sshproto sshsession sshpgp

# sshtest testsuite

lib_LIBRARIES = libssh.a
# libsshcrypt.kpure.a

SUBLIBRARIES = sshmath/libsshmath.a zlib/libz.a sshutil/libsshutil.a sshapputil/libsshapputil.a sshcrypt/libsshcrypt.a sshproto/libsshproto.a sshsession/libsshsession.a sshreadline/libsshreadline.a sshpgp/libsshpgp.a

libssh.a: $(SUBLIBRARIES)
	-rm -f libssh.a
	$(AR) rc libssh.a `for lib in $(SUBDIRS); do \
	  (cd $$lib; \
	   $(MAKE) -s list_libssh_a_objects | sed -n 's,BEGIN_FILE_LIST:\([^:]*\):END_FILE_LIST,\1,p' | sed -n 's, $$,,g; s, , '"$$lib"'/,g; p'; \
           ); \
	done;`
	$(RANLIB) libssh.a

libsshcrypt.kpure.a: sshcrypt/libsshcrypt.kpure.a
	cp sshcrypt/libsshcrypt.kpure.a .
	$(RANLIB) libsshcrypt.kpure.a

all-local: includes
includes:
	-if test '!' -d ../include; then mkdir ../include; fi
	for i in zlib/zlib.h zlib/zconf.h; do   \
	  if test -f $(srcdir)/$$i; then		  \
	    $(COPY_INCLUDE) $(srcdir)/$$i ../include;	  \
	  fi;						  \
	done
	-for dir in $(SUBDIRS); do \
		if test "$$dir" != "zlib" && test "$$dir" != "gmp"; then \
		  ( cd $$dir && $(MAKE) includes) ; \
		fi; \
	done

clean-local:
	rm -rf tmpdir-*

TAGS:
	etags `find $(SUBDIRS) -name '*.[ch]' -print`
