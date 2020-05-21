
/* Define to enable password aging.  */
#undef AGING

/* Define if struct passwd has pw_age.  */
#undef ATT_AGE

/* Define if struct passwd has pw_comment.  */
#undef ATT_COMMENT

/* Define if struct passwd has pw_quota.  */
#undef BSD_QUOTA

/* Define to use "old" dbm.  */
#undef DBM

/* Define to support 16-character passwords.  */
#undef DOUBLESIZE

/* Define if you want my getgrent routines.  */
#undef GETGRENT

/* Define if you want my getpwent routines.  */
#undef GETPWENT

/* Define if struct lastlog has ll_host */
#undef HAVE_LL_HOST

/* Working shadow group support in libc?  */
#undef HAVE_SHADOWGRP

/* Path for lastlog file.  */
#undef LASTLOG_FILE

/* Location of system mail spool directory.  */
#undef MAIL_SPOOL_DIR

/* Name of user's mail spool file if stored in user's home directory.  */
#undef MAIL_SPOOL_FILE

/* Define to support the MD5-based password hashing algorithm.  */
#undef MD5_CRYPT

/* Define to use ndbm.  */
#undef NDBM

/* Define for production version.  */
#undef NDEBUG

/* Define if you don't have a64l().  XXX */
#undef NEED_AL64

/* Define if login should support the -r flag for rlogind.  */
#undef RLOGIN

/* Define to the ruserok() "success" return value (0 or 1).  */
#undef RUSEROK

/* Define to support the shadow password file.  */
#undef SHADOWPWD

/* Define to support the shadow group file.  */
#undef SHADOWGRP

/* Define to support S/Key logins.  */
#undef SKEY

/* Define to support SecureWare(tm) long passwords.  */
#undef SW_CRYPT

/* Define to use syslog().  */
#undef USE_SYSLOG

/* Define if you have ut_host in struct utmp.  */
#undef UT_HOST

/* Path for utmp file.  */
#undef _UTMP_FILE

/* Define to ut_name if struct utmp has ut_name (not ut_user).  */
#undef UT_USER

/* Path for wtmp file.  */
#undef _WTMP_FILE

/* Defined if you have libcrypt.  */
#undef HAVE_LIBCRYPT

/* Defined if you have libcrack.  */
#undef HAVE_LIBCRACK

/* Defined if you have the ts&szs cracklib.  */
#undef HAVE_LIBCRACK_HIST

/* Defined if it includes *Pw functions.  */
#undef HAVE_LIBCRACK_PW

/*
 * Crontab and atrm.  Used in userdel.c - see user_cancel().  Verify
 * that these are correct for your distribution.  --marekm
 */

#if 0  /* old Slackware */
#define CRONTAB_COMMAND "/usr/bin/crontab -d -u %s"
#define CRONTAB_FILE "/var/cron/tabs/%s"
#else
/* Debian 0.93R6 (marekm): */
#define CRONTAB_COMMAND "/usr/bin/crontab -r -u %s"
#define CRONTAB_FILE "/var/spool/cron/crontabs/%s"
/* Red Hat 2.1 (jiivee@iki.fi): */
/* #define CRONTAB_FILE "/var/spool/cron/%s" */
#endif

#undef ATRM_COMMAND

#define CHFN_PROGRAM "/usr/bin/chfn"
#define CHSH_PROGRAM "/usr/bin/chsh"
#define GPASSWD_PROGRAM "/usr/bin/gpasswd"
#define PASSWD_PROGRAM "/usr/bin/passwd"

#define LOGIN_PROMPT "%s login: "

/* #define AUTH_METHODS */

#define LOGIN_ACCESS
#define SU_ACCESS

/* see faillog.h for more info what it is */
#define FAILLOG_LOCKTIME

/* see lmain.c and login.defs.linux */
#define CONSOLE_GROUPS

