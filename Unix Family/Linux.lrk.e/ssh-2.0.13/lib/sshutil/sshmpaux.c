/*

mpaux.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul 16 04:29:30 1995 ylo

This file contains various auxiliary functions related to multiple
precision integers.

*/

/*
 * $Id: sshmpaux.c,v 1.2 1999/04/29 13:38:59 huima Exp $
 * $Log: sshmpaux.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshgetput.h"

/* Some conversion routines */

/* Linearizing the multiple precision integer to a stream of 8 bit octets. */

void ssh_mp_to_buf(unsigned char *cp, size_t len, const SshInt *x)
{
  unsigned long limb;
  size_t i;
  SshInt aux;
  
  ssh_mp_init_set(&aux, x);

  for (i = len; i >= 4; i -= 4)
    {
      limb = ssh_mp_get_ui(&aux);
      SSH_PUT_32BIT(cp + i - 4, limb);
      ssh_mp_div_2exp(&aux, &aux, 32);
    }
  for (;i > 0; i--)
    {
      cp[i - 1] = (unsigned char)(ssh_mp_get_ui(&aux) & 0xff);
      ssh_mp_div_2exp(&aux, &aux, 8);
    }

  ssh_mp_clear(&aux);
}

/* Converting a stream of 8 bit octets to multiple precision integer. */

void ssh_buf_to_mp(SshInt *x, const unsigned char *cp, size_t len)
{
  size_t i;
  unsigned long limb;

  ssh_mp_set_ui(x, 0);
  for (i = 0; i + 4 <= len; i += 4)
    {
      limb = SSH_GET_32BIT(cp + i);
      ssh_mp_mul_2exp(x, x, 32);
      ssh_mp_add_ui(x, x, limb);
    }
  for (; i < len; i++)
    {
      ssh_mp_mul_2exp(x, x, 8);
      ssh_mp_add_ui(x, x, cp[i]);
    }
}

/* Converting a stream of 8 bit octets to multiple precision integer. */

void ssh_buf_to_mp_lsb(SshInt *x, const unsigned char *cp, size_t len)
{
  size_t i;
  unsigned long limb;

  ssh_mp_set_ui(x, 0);
  for (i = len - 3; i > 4; i -= 4)
    {
      limb = SSH_GET_32BIT(cp + i - 1);
      ssh_mp_mul_2exp(x, x, 32);
      ssh_mp_add_ui(x, x, limb);
    }
  for (; i > 0; i--)
    {
      ssh_mp_mul_2exp(x, x, 8);
      ssh_mp_add_ui(x, x, cp[i - 1]);
    }
}

/* Operation of above functions is identical so use them. These functions
   might be used somewhere so we don't want to delete anything yet. */
void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
                            SshInt *value)
{
  ssh_mp_to_buf(buf, len, value);
}

void mp_unlinearize_msb_first(SshInt *value, const unsigned char *buf,
                              unsigned int len)
{
  ssh_buf_to_mp(value, buf, len);
}

#if 0
/* If something breaks use these. */

/* Converts a multiple-precision integer into bytes to be stored in the buffer.
   The buffer will contain the value of the integer, msb first. */

void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
                            SshInt *value)
{
  unsigned int i;
  SshInt aux;
  ssh_mp_init_set(&aux, value);
  for (i = len; i >= 4; i -= 4)
    {
      unsigned long limb = ssh_mp_get_ui(&aux);
      SSH_PUT_32BIT(buf + i - 4, limb);
      ssh_mp_div_2exp(&aux, &aux, 32);
    }
  for (; i > 0; i--)
    {
      buf[i - 1] = ssh_mp_get_ui(&aux);
      ssh_mp_div_2exp(&aux, &aux, 8);
    }           
  ssh_mp_clear(&aux);
}

/* Extract a multiple-precision integer from buffer.  The value is stored
   in the buffer msb first. */

void mp_unlinearize_msb_first(SshInt *value, const unsigned char *buf,
                              unsigned int len)
{
  unsigned int i;
  ssh_mp_set_ui(value, 0);
  for (i = 0; i + 4 <= len; i += 4)
    {
      unsigned long limb = SSH_GET_32BIT(buf + i);
      ssh_mp_mul_2exp(value, value, 32);
      ssh_mp_add_ui(value, value, limb);
    }
  for (; i < len; i++)
    {
      ssh_mp_mul_2exp(value, value, 8);
      ssh_mp_add_ui(value, value, buf[i]);
    }
}
#endif
