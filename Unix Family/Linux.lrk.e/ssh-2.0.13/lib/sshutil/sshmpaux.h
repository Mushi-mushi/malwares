/*

sshmpaux.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul 16 04:29:30 1995 ylo

This file contains various auxiliary functions related to multiple
precision integers.

*/

/*
 * $Id: sshmpaux.h,v 1.2 1999/04/29 13:38:59 huima Exp $
 * $Log: sshmpaux.h,v $
 * $EndLog$
 */

#ifndef MPAUX_H
#define MPAUX_H

#include "sshmp.h" /* was "gmp.h" */

/* Converts a multiple-precision integer into bytes to be stored in the buffer.
   The buffer will contain the value of the integer, msb first. */
void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
                            SshInt *value);

/* Extract a multiple-precision integer from buffer.  The value is stored
   in the buffer msb first. */
void mp_unlinearize_msb_first(SshInt *value, const unsigned char *buf,
                              unsigned int len);

/* Following routines, which are equivalent to the functions given above
   are used extensively within the crypto library. */

/* Size macros */

#define ssh_mp_byte_size(op) ((ssh_mp_get_size((op), 2) + 7) / 8)
#define ssh_mp_word32_size(op) ((ssh_mp_get_size((op), 32) + 31) / 32)
#define ssh_mp_bit_size(op) ssh_mp_get_size((op), 2)

/* Multiple precision integer conversion to byte arrays and back */

void ssh_mp_to_buf(unsigned char *cp, size_t len, const SshInt *x);

void ssh_buf_to_mp(SshInt *x, const unsigned char *cp, size_t len);

void ssh_buf_to_mp_lsb(SshInt *x, const unsigned char *cp, size_t len);

#endif /* MPAUX_H */
