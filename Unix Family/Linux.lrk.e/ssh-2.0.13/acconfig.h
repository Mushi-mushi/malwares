/* THIS FILE WAS AUTOMAGICALLY GENERATED FROM FRAGMENTS. */
/* You should edit the fragments instead of editing this file. */

/* Package name. */
#undef PACKAGE

/* Package version. */
#undef VERSION

/* EFENCE memory debugger */
#undef EFENCE

/* Light debugging */
#undef DEBUG_LIGHT

/* Heavy debugging */
#undef DEBUG_HEAVY

/* Inet addr is broken on this system */
#undef BROKEN_INET_ADDR

/* Define this to the canonical name of your host type (e.g., 
   "sparc-sun-sunos4.0.3"). */
#undef HOSTTYPE

/* Define this to be the path of the rsh program to support executing rsh. */
#undef RSH_PATH

/* Define this to be the path of the xauth program. */
#undef XAUTH_PATH

/* Define this to be the default user path if you don't like the default. 
   See the --with-path=<path> configure option. */
#undef DEFAULT_PATH

/* Define this if sys/syslog.h needs to be included in addition to syslog.h.
   This is the case on some Ultrix versions. */
#undef NEED_SYS_SYSLOG_H

/* Define this to include libwrap (tcp_wrappers) support. */
#undef LIBWRAP
#undef HAVE_LIBWRAP

/* This is defined to pw_encrypt on Linux when using John Faugh's shadow 
   password implementation. */
#undef crypt

/* Define this if you want to support Security Dynammics SecurID
   cards. */
#undef HAVE_SECURID

/* Define this if you want to support TIS Authentication scheme. */
#undef HAVE_TIS

/* Directory containing ssh_config, ssh_known_hosts, sshd_pid, etc.  Normally
   /etc. */
#undef ETCDIR

/* Additionally define this if on SCO 3.2v5 Unix */
#undef SCO5

/* Define this if you have setpgid() (replaces setpgrp) */
#undef HAVE_SETPGID

/* Define this if you want to disable port forwardings */
#undef DISABLE_PORT_FORWARDING

/* Define this if you want to disable X11 forwarding */
#undef DISABLE_X11_FORWARDING

/* Set this to allow group writeability of $HOME, .ssh and authorized_keys */
#undef ALLOW_GROUP_WRITEABILITY

/* Define this if inet_network should be used instead of inet_addr.  This is
   the case on DGUX 5.4. */
#undef BROKEN_INET_ADDR

/* Name of the X11 directory (/{tmp,var/X}/.X11-{unix,pipe}) as a string. */
#undef X11_DIR

/* Define this if there is a compatible ssh 1.x, and SSH1_PATH, SCP1_PATH,
   and SSHD1_PATH have been set to the appropriate path. */
#undef SSH1_COMPATIBILITY

/* Path for compatible ssh 1.x. */
#undef SSH1_PATH

/* Path for compatible sshd 1.x. */
#undef SSHD1_PATH

/* Path for compatible scp 1.x. */
#undef SCP1_PATH

/* Enable ssh-agent1 compatibility in ssh-agent2. */
#undef WITH_SSH_AGENT1_COMPAT

/* Default socks server for the client. */
#undef SOCKS_DEFAULT_SERVER

/* Define this to disable server tcp forwarding (remote forwards). */
#undef SSHD2_TCPFWD_DISABLE

/* Enable the IDEA cipher. */
#undef WITH_IDEA

/* Enable the RSA code. */
#undef WITH_RSA

/* Enable the assembler crypt code. */
#undef WITH_CRYPT_ASM

/* Assember code for Blowfish included. */
#undef ASM_BLOWFISH

/* Assembler code for DES included. */
#undef ASM_DES

/* Assembler code for ARCFOUR included. */
#undef ASM_ARCFOUR

/* Assembler code for MD5 included. */
#undef ASM_MD5

/* Defined if compiled symbols are _not_ prepended with underscore `_' */
#undef HAVE_NO_SYMBOL_UNDERSCORE
/* Define this to use assembler routines in sshmath library. */
#undef SSHMATH_ASSEMBLER_SUBROUTINES

/* Define this to use assembler macros in sshmath library. */
#undef SSHMATH_ASSEMBLER_MACROS

/* Define this to use i386 assembler routines in sshmath library. */
#undef SSHMATH_I386

/* Define this to use alpha assembler routines in sshmath library. */
#undef SSHMATH_ALPHA

/* Define this to use Digital CC V5.3 assembler inline macros in sshmath
library. */
#undef SSHMATH_ALPHA_DEC_CC_ASM


/* Define this, if /usr/xpg4/include/term.h is to be used instead of
   /usr/include/term.h */
#undef HAVE_USR_XPG4_INCLUDE_TERM_H

/* Define this if you have setpgid() (replaces setpgrp) */
#undef HAVE_SETPGID

/* Define this if O_NONBLOCK does not work on your system (e.g., Ultrix). */
#undef O_NONBLOCK_BROKEN

/* Define this if speed_t is defined in stdtypes.h or otherwise gets included
   into ttymodes.c from system headers. */
#undef SPEED_T_IN_STDTYPES_H

/* If defines, this overrides "tty" as the terminal group. */
#undef TTY_GROUP

/* Define if you have SIA, Security Integration Architecture (as in
   Tru64 UNIX). */
#undef HAVE_SIA

/* Define this if your system has minor */
#undef HAVE_MINOR

/* Define this if spwd has member sp_expire*/
#undef HAVE_STRUCT_SPWD_EXPIRE

/* Define this if spwd has member sp_inact */
#undef HAVE_STRUCT_SPWD_INACT

/* Define this if utmpx has member ut_syslen */
#undef HAVE_SYSLEN_IN_UTMPX

/* Define if utmp structure has addr field. */
#undef HAVE_ADDR_IN_UTMP

/* Define if utmp structure has id field. */
#undef HAVE_ID_IN_UTMP

/* Define if utmp structure has name field. */
#undef HAVE_NAME_IN_UTMP

/* Define if utmp structure has pid field. */
#undef HAVE_PID_IN_UTMP

/* Define if you have shadow passwords in /etc/security/passwd (AIX style). */
#undef HAVE_ETC_SECURITY_PASSWD

/* Define if you have shadow passwords in /etc/security/passwd.adjunct
   (SunOS style). */
#undef HAVE_ETC_SECURITY_PASSWD_ADJUNCT
  
/* Define if you have shadow passwords in /etc/shadow (Solaris style). */
#undef HAVE_ETC_SHADOW

/* Define if you have system login defaults in /etc/default/login. */
#undef HAVE_ETC_DEFAULT_LOGIN

/* Define these if on SCO Unix. */
#undef HAVE_SCO_ETC_SHADOW
#undef SCO

/* Define this if compiling on Ultrix.  Defining this does not actually require
   shadow passwords to be present; this just includes support for them. */
#undef HAVE_ULTRIX_SHADOW_PASSWORDS

/* Define this for HP-UX 10.x shadow passwords */
#undef HAVE_HPUX_TCB_AUTH

/* Define if utmp structure has host field. */
#undef HAVE_HOST_IN_UTMP

/* Default path for utmp.  Determined by configure. */
#undef SSH_UTMP

/* Default path for wtmp.  Determined by configure. */
#undef SSH_WTMP

/* Default path for lastlog.  Determined by configure. */
#undef SSH_LASTLOG

/* This is defined if we found a lastlog file.  The presence of lastlog.h
   alone is not a sufficient indicator (at least newer BSD systems have
   lastlog but no lastlog.h. */
#undef HAVE_LASTLOG

/* Define if /var/adm/lastlog or whatever it is called is a directory
   (e.g. SGI IRIX). */
#undef LASTLOG_IS_DIR

/* Define this if libutil.a contains BSD 4.4 compatible login(), logout(),
   and logwtmp() calls. */
#undef HAVE_LIBUTIL_LOGIN

/* Location of system mail spool directory. */
#undef MAIL_SPOOL_DIRECTORY

/* Name of user's mail spool file if stored in user's home directory. */
#undef MAIL_SPOOL_FILE

/* Support for NIS+ */
#undef NIS_PLUS

/* This is defined if /var/run exists. */
#undef HAVE_VAR_RUN

/* Define this to enable setting TCP_NODELAY for tcp sockets. */
#undef ENABLE_TCP_NODELAY

/* Define this if connect(2) system call fails with nonblocking sockets. */
#undef NO_NONBLOCKING_CONNECT

/* Define this if S_IFSOCK is defined */
#undef HAVE_S_IFSOCK

/* Define this if you are using HPSUX.  HPUX uses non-standard shared
   memory communication for X, which seems to be enabled by the display name
   matching that of the local host.  This circumvents it by using the IP
   address instead of the host name in DISPLAY. */
#undef HPSUX_NONSTANDARD_X11_KLUDGE

/* Support for Secure RPC */
#undef SECURE_RPC

/* Support for Secure NFS */
#undef SECURE_NFS

/* Does struct tm have tm_gmtoff member? */
#undef HAVE_TM_GMTOFF_IN_STRUCT_TM

/* Does struct tm have tm_isdst member? */
#undef HAVE_TM_ISDST_IN_STRUCT_TM

/* Should sshtime routines avoid using system provided gmtime(3)
   and localtime(3) functions? */
#undef USE_SSH_INTERNAL_LOCALTIME

/* Enable PGP library. */
#undef WITH_PGP

