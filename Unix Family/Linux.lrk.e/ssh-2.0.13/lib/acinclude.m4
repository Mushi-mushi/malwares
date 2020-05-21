#
# acinclude.m4
#
# Author: Tero Kivinen <kivinen@ssh.fi>
# 	  Tatu Ylonen  <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
#                    All rights reserved
#
#

dnl   Add argument to CFLAGS if using gcc.
AC_DEFUN(AC_ADD_GCC_CFLAGS,
[AC_REQUIRE([AC_PROG_CC])
 if test -n "$GCC"; then
    CFLAGS="$CFLAGS $1"
 fi
 ])

dnl   Check canonical host type; abort if environment changed.  $1 is 
dnl   additional data that we guard from changing.
AC_DEFUN(AC_CANONICAL_HOST_CHECK,
[ AC_CANONICAL_HOST
  AC_MSG_CHECKING(cached information)
  hostcheck="$host"
  AC_CACHE_VAL(ac_cv_hostcheck, [ ac_cv_hostcheck="$hostcheck" ])
  if test "$ac_cv_hostcheck" != "$hostcheck"; then
    AC_MSG_RESULT(changed)
    AC_MSG_WARN(config.cache exists!)
    AC_MSG_ERROR(you must do 'make distclean' first to compile for different host or different parameters.)
  else
    AC_MSG_RESULT(ok)
  fi
])
