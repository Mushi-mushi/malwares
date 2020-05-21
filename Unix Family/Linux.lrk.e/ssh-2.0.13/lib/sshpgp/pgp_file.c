/*

pgp_file.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

File handling for OpenPGP files.

*/
/*
 * $Id: pgp_file.c,v 1.5 1999/05/03 12:54:58 tri Exp $
 * $Log: pgp_file.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshmp.h" /* was "gmp.h" */
#include "sshcrypt.h"
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpFile"

Boolean ssh_pgp_read_packet(SshFileBuffer *filebuf, SshPgpPacket *packet)
{
  unsigned char type_id;
  int packet_type;
  int i;
  size_t l;
  Boolean fr;
  Boolean partial_body;
  SshPgpPacket newpacket;
  SshBuffer partial_buf;
  Boolean partial_buf_init;

  partial_buf_init = FALSE;

  do {
    fr = ssh_file_buffer_expand(filebuf, 1);
    if (fr == FALSE)
      goto failed;
    type_id = *(ssh_buffer_ptr(&(filebuf->buf)));
    ssh_buffer_consume(&(filebuf->buf), 1);
    
    SSH_DEBUG(5, ("type_id = %d\n", type_id));

    if (type_id & 0x40) 
      {
        /* New packet header format */
        SSH_DEBUG(5, ("New packet header format\n"));
        if (partial_buf_init == FALSE)
          packet_type = type_id & 0x7f;
        fr = ssh_file_buffer_expand(filebuf, 1);
        if (fr == FALSE)
          goto failed;
        l = *(ssh_buffer_ptr(&(filebuf->buf)));
        ssh_buffer_consume(&(filebuf->buf), 1);
        if ((l >= 192) && (l <= 223))
          {
            partial_body = FALSE;
            fr = ssh_file_buffer_expand(filebuf, 1);
            if (fr == FALSE)
              goto failed;
            l = (((l - 192) << 8) + 
                 ((size_t)(*(ssh_buffer_ptr(&(filebuf->buf))))) +
                 192);
            ssh_buffer_consume(&(filebuf->buf), 1);
          }
        else if ((l >= 224) && (l <= 254))
          {
            partial_body = TRUE;
            fr = ssh_file_buffer_expand(filebuf, 1);
            if (fr == FALSE)
              goto failed;
            l = ((size_t)1) << ((*(ssh_buffer_ptr(&(filebuf->buf)))) & 0x1f);
            ssh_buffer_consume(&(filebuf->buf), 1);
            if (partial_buf_init == FALSE)
              {
                ssh_buffer_init(&partial_buf);
                partial_buf_init = TRUE;
              }
          }
        else if (l == 255)
          {
            partial_body = FALSE;
            l = 0;
            fr = ssh_file_buffer_expand(filebuf, 4);
            if (fr == FALSE)
              goto failed;
            for (i = 0; i < 4; i++)
              {
                l = (l << 8) + (*(ssh_buffer_ptr(&(filebuf->buf))));
                ssh_buffer_consume(&(filebuf->buf), 1);
              }
          }
        else
          {
            partial_body = FALSE;
          }
      }
    else
      {
        size_t ll;

        /* Old packet header format */
        SSH_DEBUG(5, ("Old packet header format\n"));
        partial_body = FALSE;
        if (partial_buf_init == FALSE)
          packet_type = (type_id & 0x7c) >> 2;
        ll = ((int)1) << (type_id & 0x03);
        fr = ssh_file_buffer_expand(filebuf, (int)ll);
        if (fr == FALSE)
          goto failed;
        l = 0;
        for (i = 0; i < ll; i++) {
          l = (l << 8) + (*(ssh_buffer_ptr(&(filebuf->buf))));
          ssh_buffer_consume(&(filebuf->buf), 1);
        }
      }

    if ((l < 1) || (l > 0x4000)) /* XXX */
      goto failed; 

    fr = ssh_file_buffer_expand(filebuf, l);
    if (fr == FALSE)
      goto failed;
    if (partial_body == FALSE)
      {
        if (packet != NULL) 
          {
            newpacket = ssh_xmalloc(sizeof (struct SshPgpPacketRec));
            newpacket->type = packet_type;
            if (partial_buf_init)
              {
                newpacket->len = l + ssh_buffer_len(&partial_buf);
                newpacket->data = ssh_xmalloc(newpacket->len);
                memcpy(newpacket->data, 
                       ssh_buffer_ptr(&partial_buf),
                       ssh_buffer_len(&partial_buf));
                memcpy(&(newpacket->data[ssh_buffer_len(&partial_buf)]), 
                       ssh_buffer_ptr(&(filebuf->buf)), 
                       l);
                ssh_buffer_uninit(&partial_buf);
                partial_buf_init = FALSE;
              }
            else
              {
                newpacket->len = l;
                newpacket->data = ssh_xmalloc(l);
                memcpy(newpacket->data, ssh_buffer_ptr(&(filebuf->buf)), l);
              }
            *packet = newpacket;
            ssh_buffer_consume(&(filebuf->buf), l);
          }
      }
    else
      {
        ssh_buffer_append(&partial_buf, ssh_buffer_ptr(&(filebuf->buf)), l);
        ssh_buffer_consume(&(filebuf->buf), l);
      }
  } while (partial_body == TRUE);

  return TRUE;

 failed:
  if (partial_buf_init == TRUE)
    ssh_buffer_uninit(&partial_buf);
  return FALSE;
}

Boolean ssh_pgp_next_packet_type(SshFileBuffer *filebuf, int *type)
{
  unsigned char type_id;
  Boolean fr;

  fr = ssh_file_buffer_expand(filebuf, 1);
  if (fr == FALSE)
    return FALSE;
  type_id = *(ssh_buffer_ptr(&(filebuf->buf)));

  if (type != NULL)
    {
      if (type_id & 0x40) 
        {
          /* New packet header format */
          *type = type_id & 0x7f;
        }
      else
        {
          /* Old packet format header */
          *type = (type_id & 0x7c) >> 2;
        }
    }
  return TRUE;
}

#endif /* WITH_PGP */
/* eof (pgp_file.c) */
