/*

pty-ptmx.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Allocating a pty using /dev/ptmx.  This is used e.g. on Solaris 2.x
and SysVr4.  (Note that Solaris 2.3 also has bsd-style ptys, but they
simply do not work.)

*/

#ifdef linux
#define _GNU_SOURCE
#endif /* linux */
#include "sshsessionincludes.h"
#include "pty-int.h"
#include "sshunixptystream.h"
#include <stropts.h>
#ifdef HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif /* HAVE_SYS_STREAM_H */
#ifdef HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif /* HAVE_SYS_CONF_H */

/* Allocates a pty using a machine-specific method, and returns the
   master side pty in *ptyfd, the child side in *ttyfd, and the name of the
   device in namebuf.  Returns TRUE if successful. */

Boolean ssh_pty_internal_allocate(int *ptyfd, int *ttyfd, char *namebuf)
{
  int ptm;
  char *pts;

#ifdef HAVE_GETPT
  ptm = getpt();
#else /* HAVE_GETPT */
  ptm = open("/dev/ptmx", O_RDWR|O_NOCTTY);
#endif /* HAVE_GETPT */
  if (ptm < 0)
    {
      ssh_warning("/dev/ptmx: %.100s", strerror(errno));
      return FALSE;
    }
  if (grantpt(ptm) < 0)
    {
      ssh_warning("grantpt: %.100s", strerror(errno));
      return FALSE;
    }
  if (unlockpt(ptm) < 0)
    {
      ssh_warning("unlockpt: %.100s", strerror(errno));
      return FALSE;
    }
  pts = ptsname(ptm);
  if (pts == NULL)
    ssh_warning("Slave pty side name could not be obtained.");
  strcpy(namebuf, pts);
  *ptyfd = ptm;

  /* Open the slave side. */
  *ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
  if (*ttyfd < 0)
    {
      ssh_warning("%.100s: %.100s", namebuf, strerror(errno));
      close(*ptyfd);
      return FALSE;
    }
  /* Push the appropriate streams modules, as described in Solaris pts(7). */
  if (ioctl(*ttyfd, I_PUSH, "ptem") < 0)
    ssh_warning("ioctl I_PUSH ptem: %.100s", strerror(errno));
  if (ioctl(*ttyfd, I_PUSH, "ldterm") < 0)
    ssh_warning("ioctl I_PUSH ldterm: %.100s", strerror(errno));
  /* HPUX does not have ttcompat, others need it.  Let's not give any
     warnings if this fails. */
  ioctl(*ttyfd, I_PUSH, "ttcompat");

  return TRUE;
}  

/* Makes the given tty the controlling tty of the current process.
   This may close and reopen the original file descriptor.  When called,
   *ttyfd should be a valid file descriptor for the slave side, and ttyname
   should contain its name (e.g., "/dev/ttyp3").  Returns FALSE if the
   controlling tty could not be set. */

Boolean ssh_pty_internal_make_ctty(int *ttyfd, const char *ttyname)
{
  int fd;
  
  /* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      (void)ioctl(fd, TIOCNOTTY, NULL);
      close(fd);
    }
#endif /* TIOCNOTTY */
  
  /* Verify that we are successfully disconnected from the controlling tty. */
  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (fd >= 0)
    {
      ssh_warning("Failed to disconnect from controlling tty.");
      close(fd);
    }

  /* Make it our controlling tty. */
#ifdef TIOCSCTTY
  ssh_debug("Setting controlling tty using TIOCSCTTY.");
  /* We ignore errors from this, because HPSUX defines TIOCSCTTY, but returns
     EINVAL with these arguments, and there is absolutely no documentation. */
  ioctl(*ttyfd, TIOCSCTTY, NULL);
#endif /* TIOCSCTTY */

#ifdef CRAY
  ssh_debug("Setting controlling tty using TCSETCTTY.");
  ioctl(*ttyfd, TCSETCTTY, NULL);
#endif

#ifdef HAVE_SETPGID
  /* This appears to be necessary on some machines...  */
  setpgid(0, 0);
#endif

  fd = open(ttyname, O_RDWR);
  if (fd < 0)
    ssh_warning("%.100s: %.100s", ttyname, strerror(errno));
  else
    close(fd);

  /* Verify that we now have a controlling tty. */
  fd = open("/dev/tty", O_WRONLY);
  if (fd < 0)
    {
      ssh_warning("open /dev/tty failed; could not set controlling tty: %s",
                  strerror(errno));
      return FALSE;
    }
  close(fd);
#if defined(HAVE_VHANGUP) && !defined(HAVE_REVOKE)
  signal(SIGHUP, SIG_IGN);
  vhangup();
  signal(SIGHUP, SIG_DFL);
  fd = open(ttyname, O_RDWR);
  if (fd == -1)
    ssh_warning("pty_make_controlling_tty: reopening controlling tty after vhangup failed for %.100s",
                ttyname);
  close(*ttyfd);
  *ttyfd = fd;
#endif /* HAVE_VHANGUP && !HAVE_REVOKE */
  return TRUE;
}
