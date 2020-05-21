/*

wtmp.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1995-1998 SSH Communications Security Ltd, Espoo, Finland
All rights reserved

Performs any logging that is normally performed when a user logs in or out.
In particular, this updates:
  - wtmp (historical records of logins)
  - utmp (list of users currently logged in)
  - lastlog (last login time for each user)

*/

/* required to get WTMPX_FILE and updwtmpx() in newer glibc */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sshsessionincludes.h"
#ifdef HAVE_UTIL_H
#include <util.h>
#endif /* HAVE_UTIL_H */
#ifdef HAVE_UTMP_H
#include <utmp.h>
#ifdef HAVE_LASTLOG_H
#include <lastlog.h> /* Some have the definitions in utmp.h. */
#endif /* HAVE_LASTLOG_H */
#endif /* HAVE_UTMP_H */
#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#ifndef SCO
#ifdef HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>  /* for minor() */
#endif /* HAVE_SYS_MKDEV_H */
#endif
#endif /* HAVE_UTMPX_H */
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif /* HAVE_USERSEC_H */
#include <sys/socket.h>
#include <netinet/in.h>  /* for in_addr */
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */
#include "sshuser.h"
/* Internal function, defined in sshunixtcp.c */
extern Boolean ssh_string_to_addr(const char *s, struct in_addr *addr);

/* Returns the time when the user last logged in, and name of the host
   from which the user logged in from.  Returns 0 if the information
   is not available.  This must be called before
   ssh_user_record_login.  The host the user logged in from will be
   returned in hostbuf. */

#ifdef LASTLOG_IS_DIR
SshTime ssh_user_get_last_login_time(SshUser user,
                                     char *hostbuf,
                                     unsigned int hostbufsize)
{
#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)
  struct lastlog ll;
  char lastlogfile[500];
  int fd;

#ifdef _PATH_LASTLOG
  snprintf(lastlogfile, sizeof(lastlogfile),
           "%.200s/%.200s", _PATH_LASTLOG, ssh_user_name(user));
#else
#ifdef LASTLOG_FILE
  snprintf(lastlogfile, sizeof(lastlogfile),
           "%.200s/%.200s", LASTLOG_FILE, ssh_user_name(user));
#else
  snprintf(lastlogfile, sizeof(lastlogfile),
           "%.200s/%.200s", SSH_LASTLOG, ssh_user_name(user));
#endif
#endif

  strcpy(hostbuf, "");

  fd = open(lastlogfile, O_RDONLY);
  if (fd < 0)
    return 0;
  if (read(fd, &ll, sizeof(ll)) != sizeof(ll))
    {
      close(fd);
      return 0;
    }
  close(fd);
  if (hostbufsize > sizeof(ll.ll_host) + 1)
    hostbufsize = sizeof(ll.ll_host) + 1;
  strncpy(hostbuf, ll.ll_host, hostbufsize);
  hostbuf[hostbufsize - 1] = 0;
  return ll.ll_time;
  
#else /* HAVE_LASTLOG_H || HAVE_LASTLOG */

  return 0;

#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */
}

#else /* LASTLOG_IS_DIR */

SshTime ssh_user_get_last_login_time(SshUser user,
                                     char *hostbuf,
                                     unsigned int hostbufsize)
{
#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)

  struct lastlog ll;
  char *lastlog;
  int fd;

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = SSH_LASTLOG;
#endif
#endif

  strcpy(hostbuf, "");

  fd = open(lastlog, O_RDONLY);
  if (fd < 0)
    return 0;
  lseek(fd, (off_t)((long)ssh_user_uid(user) * sizeof(ll)), 0);
  if (read(fd, &ll, sizeof(ll)) != sizeof(ll))
    {
      close(fd);
      return 0;
    }
  close(fd);
  if (hostbufsize > sizeof(ll.ll_host) + 1)
    hostbufsize = sizeof(ll.ll_host) + 1;
  strncpy(hostbuf, ll.ll_host, hostbufsize);
  hostbuf[hostbufsize - 1] = 0;
  return ll.ll_time;

#else /* HAVE_LASTLOG_H || HAVE_LASTLOG */

#ifdef HAVE_USERSEC_H

  char *lasthost;
  int lasttime;
  if (setuserdb(S_READ) < 0)
    return 0;
  if (getuserattr((char *)ssh_user_name(user), S_LASTTIME,
                  &lasttime, SEC_INT) < 0)
    {
      enduserdb();
      return 0;
    }
  if (getuserattr((char *)ssh_user_name(user), S_LASTHOST,
                  &lasthost, SEC_CHAR) < 0)
    {
      enduserdb();
      return 0;
    }
  strncpy(hostbuf, lasthost, hostbufsize);
  hostbuf[hostbufsize - 1] = 0;
  if (enduserdb() < 0)
    return 0;
  return lasttime;

#else /* HAVE_USERSEC_H */
  
  /* XXX getting last login time on this platform is not supported. */
  strcpy(hostbuf, "");
  return 0;

#endif /* HAVE_USERSEC_H */

#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */
}
#endif /* LASTLOG_IS_DIR */

/* Records that the user has logged in.  I wish these parts of
   operating systems were more standardized.  This code normally needs
   to be run as root.
      user    information about the user that logged in (NULL on logout)
      pid     process id of user's login shell
      ttyname name of the user's tty (slave side)
      host    name of the host the user logged in from (ip if host not known)
      ip      ip address of the host the user logged in from. */

void ssh_user_record_login(SshUser user, pid_t pid, const char *ttyname,
                           const char *host, const char *ip)
{
  int fd;

#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)
  struct lastlog ll;
  char *lastlog;
#ifdef LASTLOG_IS_DIR
  char lastlogfile[0x100];
#endif /* LASTLOG_IS_DIR */
#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */

#if defined(HAVE_UTMP_H) && !defined(HAVE_UTMPX_H)
  struct utmp u;
  const char *utmp, *wtmp;

  /* Construct an utmp/wtmp entry. */
  memset(&u, 0, sizeof(u));
#ifdef DEAD_PROCESS
  if (user == NULL)
    u.ut_type = DEAD_PROCESS; /* logout */
  else
    u.ut_type = USER_PROCESS;
#endif /* LOGIN_PROCESS */
#ifdef HAVE_PID_IN_UTMP
  u.ut_pid = pid;
#endif /* PID_IN_UTMP */
#ifdef HAVE_ID_IN_UTMP
#if defined(__sgi) || defined(CRAY)
    strncpy(u.ut_id, ttyname + 8, sizeof(u.ut_id)); /* /dev/ttyq99 -> q99 */
#else /* __sgi */
    if (sizeof(u.ut_id) > 4)
      strncpy(u.ut_id, ttyname + 5, sizeof(u.ut_id));
    else
      strncpy(u.ut_id, ttyname + strlen(ttyname) - 2, sizeof(u.ut_id));
#endif /* __sgi */
#endif /* HAVE_ID_IN_UTMP */
  strncpy(u.ut_line, ttyname + 5, sizeof(u.ut_line));
  u.ut_time = ssh_time();
#ifdef HAVE_NAME_IN_UTMP
  strncpy(u.ut_name, user ? ssh_user_name(user) : "", sizeof(u.ut_name));
#else /* HAVE_NAME_IN_UTMP */
  strncpy(u.ut_user, user ? ssh_user_name(user) : "", sizeof(u.ut_user));
#endif /* HAVE_NAME_IN_UTMP */
#ifdef HAVE_HOST_IN_UTMP
  strncpy(u.ut_host, host, sizeof(u.ut_host));
  if (strlen(host) > sizeof(u.ut_host)) {
    strncpy(u.ut_host, ip, sizeof(u.ut_host));
  }
#endif /* HAVE_HOST_IN_UTMP */
#ifdef HAVE_ADDR_IN_UTMP
  if (ip && *ip)
    {
      struct in_addr sin_addr;
      /* if address is valid, put it in the struct. */
      if(!inet_aton(ip, &sin_addr))
        memcpy(&u.ut_addr, &sin_addr, sizeof(u.ut_addr));
    }
  else
    memset(&u.ut_addr, 0, sizeof(u.ut_addr));
#endif
  /* Figure out the file names. */
#ifdef _PATH_UTMP
  utmp = _PATH_UTMP;
  wtmp = _PATH_WTMP;
#else
#ifdef UTMP_FILE
  utmp = UTMP_FILE;
  wtmp = WTMP_FILE;
#else
  utmp = SSH_UTMP;
  wtmp = SSH_WTMP;
#endif
#endif
  
#ifdef HAVE_LIBUTIL_LOGIN
  login(&u);
#else /* HAVE_LIBUTIL_LOGIN */
  /* Append an entry to wtmp. */
  fd = open(wtmp, O_WRONLY|O_APPEND);
  if (fd >= 0)
    {
      if (write(fd, &u, sizeof(u)) != sizeof(u))
        ssh_warning("Could not write %.100s: %.100s", wtmp, strerror(errno));
      close(fd);
    }

  /* Replace the proper entry in utmp, as identified by ut_line.  Append a
     new entry if the line could not be found. */
  fd = open(utmp, O_RDWR);
  if (fd >= 0)
    {
#ifdef HAVE_TTYSLOT
      int n = ttyslot();
#if defined(ultrix) || defined(NeXT)
      /* the problem is that Berkeley unix uses ttyslot() to determine
       * where in the utmp file to write and it is correct at login
       * time because the controlling tty is correct.  At logout time,
       * I think a different process runs this code and may have a
       * different (or no) controlling tty so we must search for the
       * right record to clobber.  -- corey 5/7/97 */
      if (n > 0 && user != NULL) {
#else /* ultrix || NeXT */
      if (n > 0) {
#endif /* ultrix || NeXT */
        lseek(fd, (off_t)(n*sizeof(u)), 0);
        if (write(fd, &u, sizeof(u)) != sizeof(u))
          ssh_warning("Could not write to %.100s: %.100s", 
                      utmp, strerror(errno));
      } else
#endif /* HAVE_TTYSLOT */
      while (1)
        {
          off_t offset;
          struct utmp u2;
          offset = lseek(fd, (off_t)0L, 1);
          if (read(fd, &u2, sizeof(u2)) != sizeof(u2))
            {
              lseek(fd, offset, 0);
              if (write(fd, &u, sizeof(u)) != sizeof(u))
                ssh_warning("Could not append to %.100s: %.100s", 
                            utmp, strerror(errno));
              break;
            }
#if defined(ultrix) || defined(NeXT)            /* corey */
          if (strcmp(u2.ut_line, ttyname + 5) == 0 && *u2.ut_name)
#else   /* ultrix || NeXT */
          if (strncmp(u2.ut_line, ttyname + 5, sizeof(u2.ut_line)) == 0)
#endif  /* ultrix || NeXT */
            {
              lseek(fd, offset, 0);
              if (write(fd, &u, sizeof(u)) != sizeof(u))
                ssh_warning("Could not write to %.100s: %.100s", 
                            utmp, strerror(errno));
              break;
            }
        }
      close(fd);
    }
#endif /* HAVE_LIBUTIL_LOGIN */
#endif /* HAVE_UTMP_H && !HAVE_UTMPX_H */

#ifdef HAVE_UTMPX_H
  {
    struct utmpx ux, *uxp;
    memset(&ux, 0, sizeof(ux));
    strncpy(ux.ut_line, ttyname + 5, sizeof(ux.ut_line));
    setutxent(); /* open the database and reset to first position */
    if (user == NULL)
      {
        /* logout; find previous entry for pid and zonk it */
        while ((uxp = getutxent()))
          {
            if (uxp->ut_pid != pid)
              continue;
            ux = *uxp;
            break;
          }
      }
    else
      {
        /* login: find appropriate slot for this tty */
        uxp = getutxline(&ux);
        if (uxp)
          ux = *uxp;
        strncpy(ux.ut_user, ssh_user_name(user), sizeof(ux.ut_user));
        ux.ut_type = USER_PROCESS;
      }
    endutxent();
#if defined(__sgi) || defined(SCO) || defined(linux)
    strncpy(ux.ut_id, ttyname + 8, sizeof(ux.ut_id)); /* /dev/ttyq99 -> q99 */
#else /* __sgi || SCO || linux */
    if (sizeof(ux.ut_id) > 4)
      { 
        strncpy(ux.ut_id, ttyname + 5, sizeof(ux.ut_id));
      }
    else
      {
        char buf[20];
#ifdef HAVE_MINOR
        struct stat st;
        
        buf[0] = 0;
        if (stat(ttyname, &st) == 0) {
          /* allow for 1000 /dev/pts devices */
          snprintf(buf, sizeof (buf), "P%03d", (int)minor(st.st_rdev));
        }
        strncpy(ux.ut_id, buf, sizeof(ux.ut_id));
#else /* HAVE_MINOR */
        /* if we don't have minor, we just dig out the last <= three letters
           from ttyname. */
        
        size_t ttyname_len = strlen(ttyname);
        if(ttyname_len > 3)
          {
            snprintf(buf, sizeof (buf), "P%s", &ttyname[ttyname_len - 3]);
          }
        else
          {
            snprintf(buf, sizeof (buf), "P%s", ttyname);
          }
#endif /* HAVE_MINOR */
      }
#endif /* __sgi || SCO || linux */
    ux.ut_pid = pid;

#ifdef HAVE_GETTIMEOFDAY
#ifdef HAVE_NO_TZ_IN_GETTIMEOFDAY
    gettimeofday(&ux.ut_tv);
#else
    gettimeofday(&ux.ut_tv, NULL);
#endif
#else /* HAVE_GETTIMEOFDAY */
    ux.ut_tv.tv_sec = ssh_time();
    ux.ut_tv.tv_usec = 0;
#endif /* HAVE_GETTIMEOFDAY */

    ux.ut_session = pid;
    strncpy(ux.ut_host, host, sizeof(ux.ut_host));
    ux.ut_host[sizeof(ux.ut_host) - 1] = 0;
#ifdef HAVE_SYSLEN_IN_UTMPX
    ux.ut_syslen = strlen(ux.ut_host);
#endif /* HAVE_SYSLEN_IN_UTMPX */
    setutxent(); /* reopen database and reset position to first */
#ifdef HAVE_MAKEUTX
    /*
     * modutx/makeutx notify init(1) to clean up utmpx for this pid
     * automatically if we don't manage to, for some odd reason
     */
    if (user == NULL)
        modutx(&ux);
    else
        makeutx(&ux);
#else
    pututxline(&ux);
    updwtmpx(WTMPX_FILE, &ux);
#endif
    endutxent();
  }
#endif /* HAVE_UTMPX_H */

#if defined(HAVE_LASTLOG_H) || defined(HAVE_LASTLOG)

#ifdef _PATH_LASTLOG
  lastlog = _PATH_LASTLOG;
#else
#ifdef LASTLOG_FILE
  lastlog = LASTLOG_FILE;
#else
  lastlog = SSH_LASTLOG;
#endif
#endif

  /* Update lastlog unless actually recording a logout. */
  if (user != NULL) /* only on login ... */
    {
      /* It is safer to bzero the lastlog structure first because some
         systems might have some extra fields in it (e.g. SGI) */
      memset(&ll, 0, sizeof(ll));

      /* Update lastlog. */
      ll.ll_time = ssh_time();
      strncpy(ll.ll_line, ttyname + 5, sizeof(ll.ll_line));
      strncpy(ll.ll_host, host, sizeof(ll.ll_host));
#ifdef LASTLOG_IS_DIR
      snprintf(lastlogfile, 
               sizeof (lastlogfile), 
               "%.100s/%.100s", 
               lastlog,
               ssh_user_name(user));
      fd = open(lastlogfile, O_WRONLY | O_CREAT, 0644);
      if (fd >= 0)
        {
          if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
            ssh_warning("Could not write %.100s: %.100s", 
                        lastlogfile, strerror(errno));
          close(fd);
        } 
      else 
        {
          ssh_warning("Could not open %.100s: %.100s",
                      lastlogfile, strerror(errno));
        }
#else /* LASTLOG_IS_DIR */
      fd = open(lastlog, O_RDWR);
      if (fd >= 0)
        {
          lseek(fd, (off_t)((long)ssh_user_uid(user) * sizeof(ll)), 0);
          if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
            ssh_warning("Could not write %.100s: %.100s",
                        lastlog, strerror(errno));
          close(fd);
        }
#endif /* LASTLOG_IS_DIR */
    }
#endif /* HAVE_LASTLOG_H || HAVE_LASTLOG */

#ifdef HAVE_USERSEC_H

  if (user != NULL) /* only on login ... */
    {
      int lasttime = ssh_time();
      if (setuserdb(S_WRITE) < 0)
        ssh_warning("setuserdb S_WRITE failed: %.100s", strerror(errno));
      if (putuserattr((char *)ssh_user_name(user),
                      S_LASTTIME, (void *)lasttime, SEC_INT) < 0)
        ssh_warning("putuserattr S_LASTTIME failed: %.100s", strerror(errno));
      if (putuserattr((char *)ssh_user_name(user),
                      S_LASTTTY, (void *)(ttyname + 5), SEC_CHAR) < 0)
        ssh_warning("putuserattr S_LASTTTY %.900s failed: %.100s", 
                    ttyname, strerror(errno));
      if (putuserattr((char *)ssh_user_name(user),
                      S_LASTHOST, (void *)host, SEC_CHAR) < 0)
        ssh_warning("putuserattr S_LASTHOST %.900s failed: %.100s", 
                    host, strerror(errno));
      if (putuserattr((char *)ssh_user_name(user), 0, NULL, SEC_COMMIT) < 0)
        ssh_warning("putuserattr SEC_COMMIT failed: %.100s", strerror(errno));
      if (enduserdb() < 0)
        ssh_warning("enduserdb failed: %.100s", strerror(errno));
    }
#endif /* HAVE_USERSEC_H */
}
  
/* Records that the user on the tty has logged out. */

void ssh_user_record_logout(pid_t pid, const char *ttyname)
{
#ifdef HAVE_LIBUTIL_LOGIN
  const char *line = ttyname + 5; /* /dev/ttyq8 -> ttyq8 */
  if (logout((char *)line))
    logwtmp((char *)line, "", "");
#else /* HAVE_LIBUTIL_LOGIN */
  ssh_user_record_login(NULL, pid, ttyname, "", "");
#endif /* HAVE_LIBUTIL_LOGIN */  
}
