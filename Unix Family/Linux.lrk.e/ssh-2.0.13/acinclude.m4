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

# Based on autoconf.
AC_DEFUN(AC_SSH_BIGENDIAN,
[AC_CACHE_CHECK(whether byte ordering is bigendian, ac_cv_c_bigendian,
[ac_cv_c_bigendian=unknown
# See if sys/param.h defines the BYTE_ORDER macro.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
 bogus endian macros
#endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/param.h>], [
#if BYTE_ORDER != BIG_ENDIAN
 not big endian
#endif], ac_cv_c_bigendian=yes, ac_cv_c_bigendian=no)])
if test $ac_cv_c_bigendian = unknown; then
AC_TRY_RUN([main () {
  /* Are we little or big endian?  From Harbison&Steele.  */
  union
  {
    long l;
    char c[sizeof (long)];
  } u;
  u.l = 1;
  exit (u.c[sizeof (long) - 1] == 1);
}], ac_cv_c_bigendian=no, ac_cv_c_bigendian=yes,
 AC_MSG_ERROR(Cannot cross-compile without BYTE_ORDER set in sys/param.h.))
fi])
if test $ac_cv_c_bigendian = yes; then
  AC_DEFINE(WORDS_BIGENDIAN)
fi
])
