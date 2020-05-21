#serial 1

dnl From Jim Meyering.
dnl If you use this macro in a package, you should
dnl add the following two lines to acconfig.h:
dnl   /* Define to rpl_mktime if the replacement function should be used.  */
dnl   #undef mktime
dnl
AC_DEFUN(jm_FUNC_MKTIME,
[AC_REQUIRE([AM_FUNC_MKTIME])dnl
 if test $am_cv_func_working_mktime = no; then
   AC_DEFINE_UNQUOTED(mktime, rpl_mktime)
 fi
])
