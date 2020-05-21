/* sshconf.h.  Generated automatically by configure.  */
/* sshconf.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef mode_t */

/* Define to `long' if <sys/types.h> doesn't define.  */
/* #undef off_t */

/* Define if you need to in order for stat and other things to work.  */
/* #undef _POSIX_SOURCE */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Define if the `S_IS*' macros in <sys/stat.h> do not work properly.  */
/* #undef STAT_MACROS_BROKEN */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* Define if the X Window System is missing or not being used.  */
/* #undef X_DISPLAY_MISSING */

/* Package name. */
#define PACKAGE "sshtree"

/* Package version. */
#define VERSION "1.0"

/* EFENCE memory debugger */
/* #undef EFENCE */

/* Light debugging */
/* #undef DEBUG_LIGHT */

/* Heavy debugging */
/* #undef DEBUG_HEAVY */

/* Inet addr is broken on this system */
/* #undef BROKEN_INET_ADDR */

/* Define this to the canonical name of your host type (e.g., 
   "sparc-sun-sunos4.0.3"). */
#define HOSTTYPE "i586-unknown-linux"

/* Define this to be the path of the xauth program. */
#define XAUTH_PATH "/usr/X11R6/bin/xauth"

/* Define this if sys/syslog.h needs to be included in addition to syslog.h.
   This is the case on some Ultrix versions. */
/* #undef NEED_SYS_SYSLOG_H */

/* Define this to include libwrap (tcp_wrappers) support. */
/* #undef LIBWRAP */
/* #undef HAVE_LIBWRAP */

/* This is defined to pw_encrypt on Linux when using John Faugh's shadow 
   password implementation. */
#define crypt pw_encrypt

/* Define this if you want to support Security Dynammics SecurID
   cards. */
/* #undef HAVE_SECURID */

/* Define this if you want to support TIS Authentication scheme. */
/* #undef HAVE_TIS */

/* Additionally define this if on SCO 3.2v5 Unix */
/* #undef SCO5 */

/* Define this if you want to disable port forwardings */
/* #undef DISABLE_PORT_FORWARDING */

/* Define this if you want to disable X11 forwarding */
/* #undef DISABLE_X11_FORWARDING */

/* Set this to allow group writeability of $HOME, .ssh and authorized_keys */
/* #undef ALLOW_GROUP_WRITEABILITY */

/* Define this if inet_network should be used instead of inet_addr.  This is
   the case on DGUX 5.4. */
/* #undef BROKEN_INET_ADDR */

/* Define this if there is a compatible ssh 1.x, and SSH1_PATH, SCP1_PATH,
   and SSHD1_PATH have been set to the appropriate path. */
/* #undef SSH1_COMPATIBILITY */

/* Path for compatible ssh 1.x. */
/* #undef SSH1_PATH */

/* Path for compatible sshd 1.x. */
/* #undef SSHD1_PATH */

/* Path for compatible scp 1.x. */
/* #undef SCP1_PATH */

/* Enable ssh-agent1 compatibility in ssh-agent2. */
#define WITH_SSH_AGENT1_COMPAT 1

/* Default socks server for the client. */
/* #undef SOCKS_DEFAULT_SERVER */

/* Enable the assembler crypt code. */
/* #undef WITH_CRYPT_ASM */

/* Defined if compiled symbols are _not_ prepended with underscore `_' */
#define HAVE_NO_SYMBOL_UNDERSCORE 1
/* Define this to use assembler routines in sshmath library. */
/* #undef SSHMATH_ASSEMBLER_SUBROUTINES */

/* Define this to use Digital CC V5.3 assembler inline macros in sshmath
library. */
/* #undef SSHMATH_ALPHA_DEC_CC_ASM */

/* Define this, if /usr/xpg4/include/term.h is to be used instead of
   /usr/include/term.h */
/* #undef HAVE_USR_XPG4_INCLUDE_TERM_H */

/* Define this if O_NONBLOCK does not work on your system (e.g., Ultrix). */
/* #undef O_NONBLOCK_BROKEN */

/* Define this if speed_t is defined in stdtypes.h or otherwise gets included
   into ttymodes.c from system headers. */
/* #undef SPEED_T_IN_STDTYPES_H */

/* If defines, this overrides "tty" as the terminal group. */
/* #undef TTY_GROUP */

/* Define if you have SIA, Security Integration Architecture (as in
   Tru64 UNIX). */
/* #undef HAVE_SIA */

/* Define this if your system has minor */
/* #undef HAVE_MINOR */

/* Define this if spwd has member sp_expire*/
#define HAVE_STRUCT_SPWD_EXPIRE 1

/* Define this if spwd has member sp_inact */
#define HAVE_STRUCT_SPWD_INACT 1

/* Define this if utmpx has member ut_syslen */
/* #undef HAVE_SYSLEN_IN_UTMPX */

/* Define if utmp structure has addr field. */
#define HAVE_ADDR_IN_UTMP 1

/* Define if utmp structure has id field. */
#define HAVE_ID_IN_UTMP 1

/* Define if utmp structure has name field. */
/* #undef HAVE_NAME_IN_UTMP */

/* Define if utmp structure has pid field. */
#define HAVE_PID_IN_UTMP 1

/* Define if you have shadow passwords in /etc/security/passwd (AIX style). */
/* #undef HAVE_ETC_SECURITY_PASSWD */

/* Define if you have shadow passwords in /etc/security/passwd.adjunct
   (SunOS style). */
/* #undef HAVE_ETC_SECURITY_PASSWD_ADJUNCT */

  
/* Define if you have shadow passwords in /etc/shadow (Solaris style). */
#define HAVE_ETC_SHADOW 1

/* Define if you have system login defaults in /etc/default/login. */
/* #undef HAVE_ETC_DEFAULT_LOGIN */

/* Define these if on SCO Unix. */
/* #undef HAVE_SCO_ETC_SHADOW */
/* #undef SCO */

/* Define this if compiling on Ultrix.  Defining this does not actually require
   shadow passwords to be present; this just includes support for them. */
/* #undef HAVE_ULTRIX_SHADOW_PASSWORDS */

/* Define this for HP-UX 10.x shadow passwords */
/* #undef HAVE_HPUX_TCB_AUTH */

/* Define if utmp structure has host field. */
#define HAVE_HOST_IN_UTMP 1

/* Default path for utmp.  Determined by configure. */
#define SSH_UTMP "/var/run/utmp"

/* Default path for wtmp.  Determined by configure. */
#define SSH_WTMP "/var/log/wtmp"

/* Default path for lastlog.  Determined by configure. */
#define SSH_LASTLOG "/var/log/lastlog"

/* This is defined if we found a lastlog file.  The presence of lastlog.h
   alone is not a sufficient indicator (at least newer BSD systems have
   lastlog but no lastlog.h. */
#define HAVE_LASTLOG 1

/* Define if /var/adm/lastlog or whatever it is called is a directory
   (e.g. SGI IRIX). */
/* #undef LASTLOG_IS_DIR */

/* Define this if libutil.a contains BSD 4.4 compatible login(), logout(),
   and logwtmp() calls. */
/* #undef HAVE_LIBUTIL_LOGIN */

/* Location of system mail spool directory. */
#define MAIL_SPOOL_DIRECTORY "/var/spool/mail"

/* Name of user's mail spool file if stored in user's home directory. */
/* #undef MAIL_SPOOL_FILE */

/* Support for NIS+ */
/* #undef NIS_PLUS */

/* This is defined if /var/run exists. */
#define HAVE_VAR_RUN 1

/* Define this to enable setting TCP_NODELAY for tcp sockets. */
#define ENABLE_TCP_NODELAY 1

/* Define this if connect(2) system call fails with nonblocking sockets. */
/* #undef NO_NONBLOCKING_CONNECT */

/* Define this if S_IFSOCK is defined */
#define HAVE_S_IFSOCK 1

/* Define this if you are using HPSUX.  HPUX uses non-standard shared
   memory communication for X, which seems to be enabled by the display name
   matching that of the local host.  This circumvents it by using the IP
   address instead of the host name in DISPLAY. */
/* #undef HPSUX_NONSTANDARD_X11_KLUDGE */

/* Support for Secure RPC */
/* #undef SECURE_RPC */

/* Support for Secure NFS */
/* #undef SECURE_NFS */

/* Does struct tm have tm_gmtoff member? */
/* #undef HAVE_TM_GMTOFF_IN_STRUCT_TM */

/* Does struct tm have tm_isdst member? */
#define HAVE_TM_ISDST_IN_STRUCT_TM 1

/* Should sshtime routines avoid using system provided gmtime(3)
   and localtime(3) functions? */
/* #undef USE_SSH_INTERNAL_LOCALTIME */

/* Enable PGP library. */
#define WITH_PGP 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a long.  */
#define SIZEOF_LONG 4

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* Define if you have the _getpty function.  */
/* #undef HAVE__GETPTY */

/* Define if you have the authenticate function.  */
/* #undef HAVE_AUTHENTICATE */

/* Define if you have the chmod function.  */
#define HAVE_CHMOD 1

/* Define if you have the chown function.  */
#define HAVE_CHOWN 1

/* Define if you have the clock function.  */
#define HAVE_CLOCK 1

/* Define if you have the crypt function.  */
#define HAVE_CRYPT 1

/* Define if you have the ctime function.  */
#define HAVE_CTIME 1

/* Define if you have the daemon function.  */
#define HAVE_DAEMON 1

/* Define if you have the endgrent function.  */
#define HAVE_ENDGRENT 1

/* Define if you have the endpwent function.  */
#define HAVE_ENDPWENT 1

/* Define if you have the fchmod function.  */
#define HAVE_FCHMOD 1

/* Define if you have the fchown function.  */
#define HAVE_FCHOWN 1

/* Define if you have the fstat function.  */
#define HAVE_FSTAT 1

/* Define if you have the ftruncate function.  */
#define HAVE_FTRUNCATE 1

/* Define if you have the futimes function.  */
/* #undef HAVE_FUTIMES */

/* Define if you have the getenv function.  */
#define HAVE_GETENV 1

/* Define if you have the geteuid function.  */
#define HAVE_GETEUID 1

/* Define if you have the getgid function.  */
#define HAVE_GETGID 1

/* Define if you have the getgrgid function.  */
#define HAVE_GETGRGID 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getopt function.  */
#define HAVE_GETOPT 1

/* Define if you have the getpgrp function.  */
#define HAVE_GETPGRP 1

/* Define if you have the getpid function.  */
#define HAVE_GETPID 1

/* Define if you have the getppid function.  */
#define HAVE_GETPPID 1

/* Define if you have the getpt function.  */
/* #undef HAVE_GETPT */

/* Define if you have the getpwuid function.  */
#define HAVE_GETPWUID 1

/* Define if you have the getrlimit function.  */
#define HAVE_GETRLIMIT 1

/* Define if you have the getrusage function.  */
#define HAVE_GETRUSAGE 1

/* Define if you have the getservbyname function.  */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the getservbyport function.  */
#define HAVE_GETSERVBYPORT 1

/* Define if you have the getspnam function.  */
#define HAVE_GETSPNAM 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the getuid function.  */
#define HAVE_GETUID 1

/* Define if you have the initgroups function.  */
#define HAVE_INITGROUPS 1

/* Define if you have the innetgr function.  */
#define HAVE_INNETGR 1

/* Define if you have the localtime function.  */
#define HAVE_LOCALTIME 1

/* Define if you have the lockf function.  */
#define HAVE_LOCKF 1

/* Define if you have the lstat function.  */
#define HAVE_LSTAT 1

/* Define if you have the lutimes function.  */
/* #undef HAVE_LUTIMES */

/* Define if you have the makeutx function.  */
/* #undef HAVE_MAKEUTX */

/* Define if you have the memcpy function.  */
#define HAVE_MEMCPY 1

/* Define if you have the memmove function.  */
#define HAVE_MEMMOVE 1

/* Define if you have the memset function.  */
#define HAVE_MEMSET 1

/* Define if you have the minor function.  */
/* #undef HAVE_MINOR */

/* Define if you have the nanosleep function.  */
#define HAVE_NANOSLEEP 1

/* Define if you have the openpty function.  */
#define HAVE_OPENPTY 1

/* Define if you have the popen function.  */
#define HAVE_POPEN 1

/* Define if you have the putenv function.  */
#define HAVE_PUTENV 1

/* Define if you have the pw_encrypt function.  */
#define HAVE_PW_ENCRYPT 1

/* Define if you have the random function.  */
#define HAVE_RANDOM 1

/* Define if you have the remove function.  */
#define HAVE_REMOVE 1

/* Define if you have the revoke function.  */
#define HAVE_REVOKE 1

/* Define if you have the setlogin function.  */
/* #undef HAVE_SETLOGIN */

/* Define if you have the setluid function.  */
/* #undef HAVE_SETLUID */

/* Define if you have the setpgid function.  */
#define HAVE_SETPGID 1

/* Define if you have the setpgrp function.  */
#define HAVE_SETPGRP 1

/* Define if you have the setrlimit function.  */
#define HAVE_SETRLIMIT 1

/* Define if you have the setsid function.  */
#define HAVE_SETSID 1

/* Define if you have the signal function.  */
#define HAVE_SIGNAL 1

/* Define if you have the sleep function.  */
#define HAVE_SLEEP 1

/* Define if you have the snprintf function.  */
#define HAVE_SNPRINTF 1

/* Define if you have the strcasecmp function.  */
#define HAVE_STRCASECMP 1

/* Define if you have the strchr function.  */
#define HAVE_STRCHR 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strncasecmp function.  */
#define HAVE_STRNCASECMP 1

/* Define if you have the times function.  */
#define HAVE_TIMES 1

/* Define if you have the truncate function.  */
#define HAVE_TRUNCATE 1

/* Define if you have the ttyslot function.  */
/* #undef HAVE_TTYSLOT */

/* Define if you have the ulimit function.  */
#define HAVE_ULIMIT 1

/* Define if you have the umask function.  */
#define HAVE_UMASK 1

/* Define if you have the uname function.  */
#define HAVE_UNAME 1

/* Define if you have the usleep function.  */
#define HAVE_USLEEP 1

/* Define if you have the utime function.  */
#define HAVE_UTIME 1

/* Define if you have the utimes function.  */
#define HAVE_UTIMES 1

/* Define if you have the vhangup function.  */
#define HAVE_VHANGUP 1

/* Define if you have the waitpid function.  */
#define HAVE_WAITPID 1

/* Define if you have the <arpa/inet.h> header file.  */
#define HAVE_ARPA_INET_H 1

/* Define if you have the <curses.h> header file.  */
#define HAVE_CURSES_H 1

/* Define if you have the <dirent.h> header file.  */
#define HAVE_DIRENT_H 1

/* Define if you have the <endian.h> header file.  */
#define HAVE_ENDIAN_H 1

/* Define if you have the <grp.h> header file.  */
#define HAVE_GRP_H 1

/* Define if you have the <lastlog.h> header file.  */
#define HAVE_LASTLOG_H 1

/* Define if you have the <libutil.h> header file.  */
/* #undef HAVE_LIBUTIL_H */

/* Define if you have the <login_cap.h> header file.  */
/* #undef HAVE_LOGIN_CAP_H */

/* Define if you have the <machine/endian.h> header file.  */
/* #undef HAVE_MACHINE_ENDIAN_H */

/* Define if you have the <machine/spl.h> header file.  */
/* #undef HAVE_MACHINE_SPL_H */

/* Define if you have the <ndir.h> header file.  */
/* #undef HAVE_NDIR_H */

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1

/* Define if you have the <netgroup.h> header file.  */
/* #undef HAVE_NETGROUP_H */

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <netinet/in_systm.h> header file.  */
#define HAVE_NETINET_IN_SYSTM_H 1

/* Define if you have the <paths.h> header file.  */
#define HAVE_PATHS_H 1

/* Define if you have the <pwd.h> header file.  */
#define HAVE_PWD_H 1

/* Define if you have the <rusage.h> header file.  */
/* #undef HAVE_RUSAGE_H */

/* Define if you have the <sgtty.h> header file.  */
/* #undef HAVE_SGTTY_H */

/* Define if you have the <shadow.h> header file.  */
#define HAVE_SHADOW_H 1

/* Define if you have the <sia.h> header file.  */
/* #undef HAVE_SIA_H */

/* Define if you have the <sys/callout.h> header file.  */
/* #undef HAVE_SYS_CALLOUT_H */

/* Define if you have the <sys/conf.h> header file.  */
/* #undef HAVE_SYS_CONF_H */

/* Define if you have the <sys/dir.h> header file.  */
/* #undef HAVE_SYS_DIR_H */

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/mkdev.h> header file.  */
/* #undef HAVE_SYS_MKDEV_H */

/* Define if you have the <sys/ndir.h> header file.  */
/* #undef HAVE_SYS_NDIR_H */

/* Define if you have the <sys/resource.h> header file.  */
#define HAVE_SYS_RESOURCE_H 1

/* Define if you have the <sys/select.h> header file.  */
/* #undef HAVE_SYS_SELECT_H */

/* Define if you have the <sys/stream.h> header file.  */
/* #undef HAVE_SYS_STREAM_H */

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/un.h> header file.  */
#define HAVE_SYS_UN_H 1

/* Define if you have the <sys/utsname.h> header file.  */
#define HAVE_SYS_UTSNAME_H 1

/* Define if you have the <term.h> header file.  */
#define HAVE_TERM_H 1

/* Define if you have the <termcap.h> header file.  */
#define HAVE_TERMCAP_H 1

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

/* Define if you have the <util.h> header file.  */
/* #undef HAVE_UTIL_H */

/* Define if you have the <utime.h> header file.  */
#define HAVE_UTIME_H 1

/* Define if you have the <utmp.h> header file.  */
#define HAVE_UTMP_H 1

/* Define if you have the <utmpx.h> header file.  */
/* #undef HAVE_UTMPX_H */

/* Define if you have the auth library (-lauth).  */
/* #undef HAVE_LIBAUTH */

/* Define if you have the bsd library (-lbsd).  */
#define HAVE_LIBBSD 1

/* Define if you have the crypt library (-lcrypt).  */
/* #undef HAVE_LIBCRYPT */

/* Define if you have the gen library (-lgen).  */
/* #undef HAVE_LIBGEN */

/* Define if you have the inet library (-linet).  */
/* #undef HAVE_LIBINET */

/* Define if you have the ncurses library (-lncurses).  */
#define HAVE_LIBNCURSES 1

/* Define if you have the nsl library (-lnsl).  */
/* #undef HAVE_LIBNSL */

/* Define if you have the s library (-ls).  */
/* #undef HAVE_LIBS */

/* Define if you have the sec library (-lsec).  */
/* #undef HAVE_LIBSEC */

/* Define if you have the seq library (-lseq).  */
/* #undef HAVE_LIBSEQ */

/* Define if you have the shadow library (-lshadow).  */
#define HAVE_LIBSHADOW 1

/* Define if you have the socket library (-lsocket).  */
/* #undef HAVE_LIBSOCKET */

/* Define if you have the sun library (-lsun).  */
/* #undef HAVE_LIBSUN */

/* Define if you have the termcap library (-ltermcap).  */
#define HAVE_LIBTERMCAP 1

/* Define if you have the xcurses library (-lxcurses).  */
/* #undef HAVE_LIBXCURSES */
