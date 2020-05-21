/*

  sshttyflags.h
  
  Author: Sami Lehtinen <sjl@ssh.fi>

  Prototypes for public stty-mode manipulation functions.
  
*/

/*
 * $Id: sshttyflags.h,v 1.2 1999/02/17 06:56:28 tri Exp $
 * $Log: sshttyflags.h,v $
 * $EndLog$
 */

#ifndef SSHTTYFLAGS_H
#define SSHTTYFLAGS_H

void ssh_decode_tty_flags(int fd, unsigned char *buf, size_t buf_len);
void ssh_encode_tty_flags(int fd, unsigned char **buf, size_t *buf_len);

#endif /* SSHTTYFLAGS_H */
