/*

tty.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

#include "sshsessionincludes.h"
#include "sshtty.h"

Boolean ssh_in_raw_mode = FALSE;
Boolean ssh_in_non_blocking_mode = FALSE;

/* Terminal modes, as saved by enter_raw_mode. */
#ifdef USING_TERMIOS
static struct termios saved_tio;
#endif
#ifdef USING_SGTTY
static struct sgttyb saved_tio;
#endif

/* Returns the user's terminal to normal mode if it had been put in raw 
   mode. */

void ssh_leave_raw_mode(int fd)
{
  if (fd < 0)
    fd = fileno(stdin);
  if (!ssh_in_raw_mode)
    return;
  ssh_in_raw_mode = FALSE;
  if (isatty(fd))
    {
#ifdef USING_TERMIOS
      if (tcsetattr(fd, TCSADRAIN, &saved_tio) < 0)
        perror("tcsetattr");
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
      if (ioctl(fd, TIOCSETP, &saved_tio) < 0)
        perror("ioctl(stdin, TIOCSETP, ...)");
#endif /* USING_SGTTY */
    }
}

/* Puts the user\'s terminal in raw mode. */

void ssh_enter_raw_mode(int fd)
{
  if (fd < 0)
    fd = fileno(stdin);
  if (isatty(fd))
    {
#ifdef USING_TERMIOS
      struct termios tio;

      if (tcgetattr(fd, &tio) < 0)
        perror("tcgetattr");
      saved_tio = tio;
      tio.c_iflag |= IGNPAR;
      tio.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
      tio.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL);
#ifdef IEXTEN
      tio.c_lflag &= ~IEXTEN;
#endif /* IEXTEN */
      tio.c_oflag &= ~OPOST;
      tio.c_cc[VMIN] = 1;
      tio.c_cc[VTIME] = 0;
      if (tcsetattr(fd, TCSADRAIN, &tio) < 0)
        perror("tcsetattr");
      ssh_in_raw_mode = TRUE;
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
      struct sgttyb tio;

      if (ioctl(fd, TIOCGETP, &tio) < 0)
        perror("ioctl(stdin, TIOCGETP, ...)");
      saved_tio = tio;
      tio.sg_flags &= ~(CBREAK | ECHO | CRMOD | LCASE | TANDEM);
      tio.sg_flags |= (RAW | ANYP);
      if (ioctl(fd, TIOCSETP, &tio) < 0)
        perror("ioctl(stdin, TIOCSETP, ...)");
      ssh_in_raw_mode = TRUE;
#endif /* USING_SGTTY */
    }
}  

/* Puts terminal in non-blocking mode. */

void ssh_leave_non_blocking(int fd)
{
  if (fd < 0)
    fd = fileno(stdin);
  if (ssh_in_non_blocking_mode)
    {
      (void)fcntl(fd, F_SETFL, 0);
      ssh_in_non_blocking_mode = FALSE;
    }
}

/* Restores terminal to blocking mode. */

void ssh_enter_non_blocking(int fd)
{
  if (fd < 0)
    fd = fileno(stdin);
  ssh_in_non_blocking_mode = TRUE;
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(fd, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(fd, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
}
