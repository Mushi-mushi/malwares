/*

  nociph.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov  2 04:22:51 1996 [mkojo]

  Cipher 'none'.

  */

/*
 * $Id: nociph.h,v 1.6 1998/12/03 19:48:20 mkojo Exp $
 * $Log: nociph.h,v $
 * $EndLog$
 */

#ifndef NOCIPH_H
#define NOCIPH_H

void ssh_none_cipher(void *context, unsigned char *dest,
                     const unsigned char *src, size_t len,
                     unsigned char *iv);

#endif /* NOCIPH_H */
