/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to the type of elements in the array set by `getgroups'.
   Usually this is either `int' or `gid_t'.  */
#define GETGROUPS_T gid_t

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef gid_t */

/* Define if your struct stat has st_rdev.  */
#define HAVE_ST_RDEV 1

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define if utime(file, NULL) sets file's timestamp to the present.  */
#define HAVE_UTIME_NULL 1

/* Define to `long' if <sys/types.h> doesn't define.  */
/* #undef off_t */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef uid_t */

/* Define if you do not have <strings.h>, index, bzero, etc..  */
#define USG 1

/* Define to enable password aging.  */
#define AGING 1

/* Define if struct passwd has pw_age.  */
/* #undef ATT_AGE */

/* Define if struct passwd has pw_comment.  */
/* #undef ATT_COMMENT */

/* Define if struct passwd has pw_quota.  */
/* #undef BSD_QUOTA */

/* Define if struct lastlog has ll_host */
#define HAVE_LL_HOST 1

/* Working shadow group support in libc?  */
#define HAVE_SHADOWGRP 1

/* Path for lastlog file.  */
#define LASTLOG_FILE "/var/log/lastlog"

/* Location of system mail spool directory.  */
#define MAIL_SPOOL_DIR "/var/spool/mail"

/* Define to support the MD5-based password hashing algorithm.  */
#define MD5_CRYPT 1

/* Define for production version.  */
#define NDEBUG 1

/* Define if you don't have a64l().  XXX */
#define NEED_AL64 1

/* Define if login should support the -r flag for rlogind.  */
#define RLOGIN 1

/* Define to the ruserok() "success" return value (0 or 1).  */
#define RUSEROK 0

/* Define to support the shadow password file.  */
#define SHADOWPWD 1

/* Define to support the shadow group file.  */
/* #undef SHADOWGRP */

/* Define to support S/Key logins.  */
/* #undef SKEY */

/* Define to use syslog().  */
#define USE_SYSLOG 1

/* Define if you have ut_host in struct utmp.  */
#define UT_HOST 1

/* Path for utmp file.  */
#define _UTMP_FILE "/var/run/utmp"

/* Define to ut_name if struct utmp has ut_name (not ut_user).  */
/* #undef UT_USER */

/* Path for wtmp file.  */
#define _WTMP_FILE "/var/log/wtmp"

/* Defined if you have libcrypt.  */
/* #undef HAVE_LIBCRYPT */

/* Defined if you have libcrack.  */
/* #undef HAVE_LIBCRACK */

/* Defined if you have the ts&szs cracklib.  */
/* #undef HAVE_LIBCRACK_HIST */

/* Defined if it includes *Pw functions.  */
/* #undef HAVE_LIBCRACK_PW */

#define CHFN_PROGRAM "/usr/bin/chfn"
#define CHSH_PROGRAM "/usr/bin/chsh"
#define GPASSWD_PROGRAM "/usr/bin/gpasswd"
#define PASSWD_PROGRAM "/usr/bin/passwd"

#define LOGIN_ACCESS
#define SU_ACCESS

/* see faillog.h for more info what it is */
#define FAILLOG_LOCKTIME

/* see lmain.c and login.defs.linux */
#define CONSOLE_GROUPS

/* Define if you have the getgroups function.  */
#define HAVE_GETGROUPS 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getspnam function.  */
#define HAVE_GETSPNAM 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the getusershell function.  */
#define HAVE_GETUSERSHELL 1

/* Define if you have the getutent function.  */
#define HAVE_GETUTENT 1

/* Define if you have the initgroups function.  */
#define HAVE_INITGROUPS 1

/* Define if you have the setgroups function.  */
#define HAVE_SETGROUPS 1

/* Define if you have the sigaction function.  */
#define HAVE_SIGACTION 1

/* Define if you have the strcspn function.  */
#define HAVE_STRCSPN 1

/* Define if you have the strftime function.  */
#define HAVE_STRFTIME 1

/* Define if you have the strptime function.  */
#define HAVE_STRPTIME 1

/* Define if you have the strspn function.  */
#define HAVE_STRSPN 1

/* Define if you have the strtol function.  */
#define HAVE_STRTOL 1

/* Define if you have the <dirent.h> header file.  */
#define HAVE_DIRENT_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <gshadow.h> header file.  */
/* #undef HAVE_GSHADOW_H */

/* Define if you have the <lastlog.h> header file.  */
#define HAVE_LASTLOG_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <ndir.h> header file.  */
/* #undef HAVE_NDIR_H */

/* Define if you have the <paths.h> header file.  */
#define HAVE_PATHS_H 1

/* Define if you have the <sgtty.h> header file.  */
/* #undef HAVE_SGTTY_H */

/* Define if you have the <shadow.h> header file.  */
#define HAVE_SHADOW_H 1

/* Define if you have the <sys/dir.h> header file.  */
/* #undef HAVE_SYS_DIR_H */

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/ndir.h> header file.  */
/* #undef HAVE_SYS_NDIR_H */

/* Define if you have the <sys/resource.h> header file.  */
#define HAVE_SYS_RESOURCE_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <termio.h> header file.  */
#define HAVE_TERMIO_H 1

/* Define if you have the <termios.h> header file.  */
#define HAVE_TERMIOS_H 1

/* Define if you have the <ulimit.h> header file.  */
#define HAVE_ULIMIT_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the <usersec.h> header file.  */
/* #undef HAVE_USERSEC_H */

/* Define if you have the <utime.h> header file.  */
#define HAVE_UTIME_H 1

/* Define if you have the <utmp.h> header file.  */
#define HAVE_UTMP_H 1

/* Define if you have the <utmpx.h> header file.  */
/* #undef HAVE_UTMPX_H */
