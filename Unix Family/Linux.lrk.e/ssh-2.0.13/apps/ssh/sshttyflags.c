/*

  sshttyflags.c
  
  Author: Tatu Ylonen <ylo@ssh.fi>
          Sami Lehtinen <sjl@ssh.fi>
  
  Based on ttymodes.c from ssh-1.2.26.

  Encoding and decoding of terminal modes in a portable way.  Much of
  the format is defined in sshttyflagsi.h; it is included multiple
  times into this file with the appropriate macro definitions to
  generate the suitable code.
*/

/*
 * $Id: sshttyflags.c,v 1.6 1999/05/04 19:25:52 kivinen Exp $
 * $Log: sshttyflags.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#define USING_TERMIOS
#endif /* HAVE_TERMIOS_H */
#if defined(HAVE_SGTTY_H) && !defined(USING_TERMIOS)
#include <sgtty.h>
#define USING_SGTTY
#endif /* HAVE_SGTTY_H && !USING_TERMIOS*/
#if !defined(USING_SGTTY) && !defined(USING_TERMIOS)
  ERROR NO TERMIOS OR SGTTY
#endif
#include "sshbuffer.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshTtyFlags"
  
#define TTY_OP_END      0
#define TTY_OP_ISPEED   128
#define TTY_OP_OSPEED   129

/* Speed extraction & setting macros for sgtty. */

#ifdef USING_SGTTY
#define cfgetospeed(tio)        ((tio)->sg_ospeed)
#define cfgetispeed(tio)        ((tio)->sg_ispeed)
#define cfsetospeed(tio, spd)   ((tio)->sg_ospeed = (spd), 0)
#define cfsetispeed(tio, spd)   ((tio)->sg_ispeed = (spd), 0)
#ifndef SPEED_T_IN_STDTYPES_H
typedef char speed_t;
#endif
#endif

/* Converts POSIX speed_t to a baud rate.  The values of the constants
   for speed_t are not themselves portable. */

static int speed_to_baud(speed_t speed)
{
  switch (speed)
    {
    case B0:
      return 0;
    case B50:
      return 50;
    case B75:
      return 75;
    case B110:
      return 110;
    case B134:
      return 134;
    case B150:
      return 150;
    case B200:
      return 200;
    case B300:
      return 300;
    case B600:
      return 600;
    case B1200:
      return 1200;
    case B1800:
      return 1800;
    case B2400:
      return 2400;
    case B4800:
      return 4800;
    case B9600:
      return 9600;

#ifdef B19200
    case B19200:
      return 19200;
#else /* B19200 */
#ifdef EXTA
    case EXTA:
      return 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
    case B38400:
      return 38400;
#else /* B38400 */
#ifdef EXTB
    case EXTB:
      return 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
    case B7200:
      return 7200;
#endif /* B7200 */
#ifdef B14400
    case B14400:
      return 14400;
#endif /* B14400 */
#ifdef B28800
    case B28800:
      return 28800;
#endif /* B28800 */
#ifdef B57600
    case B57600:
      return 57600;
#endif /* B57600 */
#ifdef B76800
    case B76800:
      return 76800;
#endif /* B76800 */
#ifdef B115200
    case B115200:
      return 115200;
#endif /* B115200 */
#ifdef B230400
    case B230400:
      return 230400;
#endif /* B230400 */
    default:
      return 9600;
    }
}

/* Converts a numeric baud rate to a POSIX speed_t. */

static speed_t baud_to_speed(int baud)
{
  switch (baud)
    {
    case 0:
      return B0;
    case 50:
      return B50;
    case 75:
      return B75;
    case 110:
      return B110;
    case 134:
      return B134;
    case 150:
      return B150;
    case 200:
      return B200;
    case 300:
      return B300;
    case 600:
      return B600;
    case 1200:
      return B1200;
    case 1800:
      return B1800;
    case 2400:
      return B2400;
    case 4800:
      return B4800;
    case 9600:
      return B9600;

#ifdef B19200
    case 19200:
      return B19200;
#else /* B19200 */
#ifdef EXTA
    case 19200:
      return EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
    case 38400:
      return B38400;
#else /* B38400 */
#ifdef EXTB
    case 38400:
      return EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
    case 7200:
      return B7200;
#endif /* B7200 */
#ifdef B14400
    case 14400:
      return B14400;
#endif /* B14400 */
#ifdef B28800
    case 28800:
      return B28800;
#endif /* B28800 */
#ifdef B57600
    case 57600:
      return B57600;
#endif /* B57600 */
#ifdef B76800
    case 76800:
      return B76800;
#endif /* B76800 */
#ifdef B115200
    case 115200:
      return B115200;
#endif /* B115200 */
#ifdef B230400
    case 230400:
      return B230400;
#endif /* B230400 */
    default:
      return B9600;
    }
}

/* Helper macros for ssh_encode_tty_flags */

#undef PUT_CHAR
#define PUT_CHAR(argument)  \
do { \
    ssh_encode_buffer(&buffer, \
        SSH_FORMAT_CHAR, (unsigned int) (argument), \
        SSH_FORMAT_END); \
} while (0)

#undef PUT_UINT32
#define PUT_UINT32(argument)  \
do { \
    ssh_encode_buffer(&buffer, \
        SSH_FORMAT_UINT32, (SshUInt32) (argument), \
        SSH_FORMAT_END); \
} while (0)

/* Encodes terminal modes for the terminal referenced by fd in a
   portable manner, and appends the modes to a buffer being
   constructed. Stores constructed buffers len to buf_len. This call
   always succeeds, but if an error happens during encoding, buf will
   be empty and buf_len will be 0 */
void ssh_encode_tty_flags(int fd, unsigned char **buf, size_t *buf_len)
     /*void tty_make_modes(int fd)*/
{
  SshBuffer buffer;  
#ifdef USING_TERMIOS
  struct termios tio;
#endif
#ifdef USING_SGTTY
  struct sgttyb tio;
  struct tchars tiotc;
  struct ltchars tioltc;
  int tiolm;
#ifdef TIOCGSTAT
  struct tstatus tiots;
#endif /* TIOCGSTAT */
#endif /* USING_SGTTY */
  int baud;

  if (!isatty(fd))
    {
      SSH_TRACE(2, ("Not a tty. (fd = %d)", fd));
      *buf = ssh_xstrdup("");
      *buf_len = 0;
      return;
    }
  
  ssh_buffer_init(&buffer);

  /* Get the modes. */
#ifdef USING_TERMIOS
  if (tcgetattr(fd, &tio) < 0)
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("tcgetattr: %.100s", strerror(errno));
      goto error;
    }
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  if (ioctl(fd, TIOCGETP, &tio) < 0)
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("ioctl(fd, TIOCGETP, ...): %.100s", strerror(errno));
      goto error;
    }
  if (ioctl(fd, TIOCGETC, &tiotc) < 0)
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("ioctl(fd, TIOCGETC, ...): %.100s", strerror(errno));
      goto error;
    }
  if (ioctl(fd, TIOCLGET, &tiolm) < 0)
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("ioctl(fd, TIOCLGET, ...): %.100s", strerror(errno));
      goto error;
    }
  if (ioctl(fd, TIOCGLTC, &tioltc) < 0)
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("ioctl(fd, TIOCGLTC, ...): %.100s", strerror(errno));
      goto error;
    }
#ifdef TIOCGSTAT
  if (ioctl(fd, TIOCGSTAT, &tiots) < 0) 
    {
      PUT_CHAR(TTY_OP_END);
      ssh_warning("ioctl(fd, TIOCGSTAT, ...): %.100s", strerror(errno));
      goto error;
    }
#endif /* TIOCGSTAT */
  /* termio's ECHOE is really both LCRTBS and LCRTERA - so wire them
     together */
  if (tiolm & LCRTBS)
    tiolm |= LCRTERA;
#endif /* USING_SGTTY */

  /* Store input and output baud rates. */
  baud = speed_to_baud(cfgetospeed(&tio));
  PUT_CHAR(TTY_OP_OSPEED);
  PUT_UINT32(baud);
  baud = speed_to_baud(cfgetispeed(&tio));
  PUT_CHAR(TTY_OP_ISPEED);
  PUT_UINT32(baud);

  /* Store values of mode flags. */
#ifdef USING_TERMIOS
#define TTYCHAR(NAME, OP) \
  PUT_CHAR(OP); PUT_UINT32(tio.c_cc[NAME]);
#define TTYMODE(NAME, FIELD, OP) \
  PUT_CHAR(OP); PUT_UINT32((tio.FIELD & NAME) != 0);
#define SGTTYCHAR(NAME, OP)
#define SGTTYMODE(NAME, FIELD, OP)
#define SGTTYMODEN(NAME, FIELD, OP)
#endif /* USING_TERMIOS */

#ifdef USING_SGTTY
#define TTYCHAR(NAME, OP)
#define TTYMODE(NAME, FIELD, OP)
#define SGTTYCHAR(NAME, OP) \
  PUT_CHAR(OP); PUT_UINT32(NAME);
#define SGTTYMODE(NAME, FIELD, OP) \
  PUT_CHAR(OP); PUT_UINT32((FIELD & NAME) != 0);
#define SGTTYMODEN(NAME, FIELD, OP) \
  PUT_CHAR(OP); PUT_UINT32((FIELD & NAME) == 0);
#endif /* USING_SGTTY */

#include "sshttyflagsi.h"

#undef TTYCHAR
#undef TTYMODE
#undef SGTTYCHAR
#undef SGTTYMODE
#undef SGTTYMODEN

  /* Mark end of mode data. */
  PUT_CHAR(TTY_OP_END);

  *buf_len = ssh_buffer_len(&buffer);
  *buf = ssh_xmemdup(ssh_buffer_ptr(&buffer), *buf_len);
  ssh_buffer_uninit(&buffer);

  SSH_DEBUG_HEXDUMP(5, ("encoded tty-flags buffer"), *buf, *buf_len);
  
  return;

 error:
  ssh_buffer_uninit(&buffer);
  *buf = ssh_xstrdup("");
  *buf_len = 0;
}

#undef PUT_UINT32
#undef PUT_CHAR

#undef GET_CHAR
#undef GET_UINT32

unsigned char tty_buffer_get_char(SshBuffer *buffer)
{
  unsigned int value;
  ssh_decode_buffer(buffer,
                    SSH_FORMAT_CHAR, &value,
                    SSH_FORMAT_END);

  return value;
}

SshUInt32 tty_buffer_get_uint32(SshBuffer *buffer)
{
  SshUInt32 value;
  ssh_decode_buffer(buffer,
                    SSH_FORMAT_UINT32, &value,
                    SSH_FORMAT_END);

  return value;
}

#define GET_CHAR() \
tty_buffer_get_char(&buffer)

#define GET_UINT32() \
tty_buffer_get_uint32(&buffer)

/* Decodes terminal modes for the terminal referenced by fd in a portable
   manner from a packet being read. */

void ssh_decode_tty_flags(int fd, unsigned char *buf, size_t buf_len)
{
  SshBuffer buffer;
  
#ifdef USING_TERMIOS
  struct termios tio;
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  struct sgttyb tio;
  struct tchars tiotc;
  struct ltchars tioltc;
  int tiolm;
#ifdef TIOCGSTAT
  struct tstatus tiots;
#endif /* TIOCGSTAT */
#endif
  int opcode, baud;

  if (!isatty(fd))
    {
      SSH_TRACE(2, ("Not a tty. (fd = %d)", fd));
      return;
    }

  if (buf_len == 0)
    return;
  
  SSH_DEBUG_HEXDUMP(5, ("received tty-flags buffer"), buf, buf_len);

  ssh_buffer_init(&buffer);

  ssh_buffer_append(&buffer, buf, buf_len);
  
  /* Get old attributes for the terminal.  We will modify these flags. 
     I am hoping that if there are any machine-specific modes, they will
     initially have reasonable values. */
#ifdef USING_TERMIOS
  if (tcgetattr(fd, &tio) < 0)
    return;
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  if (ioctl(fd, TIOCGETP, &tio) < 0)
    return;
  if (ioctl(fd, TIOCGETC, &tiotc) < 0)
    return;
  if (ioctl(fd, TIOCLGET, &tiolm) < 0)
    return;
  if (ioctl(fd, TIOCGLTC, &tioltc) < 0)
    return;
#ifdef TIOCGSTAT
  if (ioctl(fd, TIOCGSTAT, &tiots) < 0)
    return;
#endif /* TIOCGSTAT */
#endif /* USING_SGTTY */

  for (;;)
    {
      ssh_decode_buffer(&buffer,
                    SSH_FORMAT_CHAR, &opcode,
                    SSH_FORMAT_END);
      
      switch(opcode)
        {
        case TTY_OP_END:
          goto set;

        case TTY_OP_ISPEED:
          baud = GET_UINT32();
          if (cfsetispeed(&tio, baud_to_speed(baud)) < 0)
            ssh_warning("cfsetispeed failed for %d", baud);
          break;

        case TTY_OP_OSPEED:
          baud = GET_UINT32();
          if (cfsetospeed(&tio, baud_to_speed(baud)) < 0)
            ssh_warning("cfsetospeed failed for %d", baud);
          break;

#ifdef USING_TERMIOS
#define TTYCHAR(NAME, OP)                               \
        case OP:                                        \
          tio.c_cc[NAME] = GET_UINT32();                \
          break;
#define TTYMODE(NAME, FIELD, OP)                        \
        case OP:                                        \
          if (GET_UINT32())                     \
            tio.FIELD |= NAME;                          \
          else                                          \
            tio.FIELD &= ~NAME;                         \
          break;
#define SGTTYCHAR(NAME, OP)
#define SGTTYMODE(NAME, FIELD, OP)
#define SGTTYMODEN(NAME, FIELD, OP)
#endif /* USING_TERMIOS */

#ifdef USING_SGTTY
#define TTYCHAR(NAME, OP)
#define TTYMODE(NAME, FIELD, OP)
#define SGTTYCHAR(NAME, OP)                             \
        case OP:                                        \
          NAME = GET_UINT32();                  \
          break;
#define SGTTYMODE(NAME, FIELD, OP)                      \
        case OP:                                        \
          if (GET_UINT32())                     \
            FIELD |= NAME;                              \
          else                                          \
            FIELD &= ~NAME;                             \
          break;
#define SGTTYMODEN(NAME, FIELD, OP)                     \
        case OP:                                        \
          if (GET_UINT32())                     \
            FIELD &= ~NAME;                             \
          else                                          \
            FIELD |= NAME;                              \
          break;
#endif /* USING_SGTTY */

#include "sshttyflagsi.h"

#undef TTYCHAR
#undef TTYMODE
#undef SGTTYCHAR
#undef SGTTYMODE
#undef SGTTYMODEN

        default:
          SSH_TRACE(1, ("Ignoring unsupported tty mode opcode %d (0x%x)",
                        opcode, opcode));
          /* Opcodes 0 to 160 are defined to have a uint32 argument. */
          if (opcode >= 0 && opcode < 160)
            {
              (void)GET_UINT32();
              break;
            }
          /* It is a truly undefined opcode (160 to 255).  We have no idea
             about its arguments.  So we must stop parsing.  Note that some
             data may be left in the packet; hopefully there is nothing more
             coming after the mode data. */
          ssh_warning("ssh_decode_tty_flags: unknown opcode %d", opcode);
          goto set;
        }
    }

 set:
  /* Set the new modes for the terminal. */
#ifdef USING_TERMIOS
  if (tcsetattr(fd, TCSANOW, &tio) < 0)
    ssh_warning("Setting tty modes failed: %.100s", strerror(errno));
#endif /* USING_TERMIOS */
#ifdef USING_SGTTY
  /* termio's ECHOE is really both LCRTBS and LCRTERA -
     so wire them together */
  if (tiolm & LCRTERA)
    tiolm |= LCRTBS;
  if (ioctl(fd, TIOCSETP, &tio) < 0
      || ioctl(fd, TIOCSETC, &tiotc) < 0
      || ioctl(fd, TIOCLSET, &tiolm) < 0
      || ioctl(fd, TIOCSLTC, &tioltc) < 0
#ifdef TIOCSSTAT
      || ioctl(fd, TIOCSSTAT, &tiots) < 0
#endif /* TIOCSSTAT */
     ) 
    ssh_warning("Setting tty modes failed: %.100s", strerror(errno));
#endif /* USING_SGTTY */
}

#undef GET_CHAR
#undef GET_UINT32
