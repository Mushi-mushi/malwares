/*

pgp_keydb.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Find keys from pgp keyfiles.

*/
/*
 * $Id: pgp_keydb.c,v 1.4 1999/04/07 05:45:59 tri Exp $
 * $Log: pgp_keydb.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshmatch.h"
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpKeyDB"

/* Compare two key fingerprints.  Ignore case and whitespace.
   Return TRUE if fingerprints are same. */
static Boolean ssh_pgp_fingerprint_match(const char *f1, const char *f2);

/* Get a next name identifier in the keyring.  If none is found before
   the eof or the next key, NULL is returned.  Otherwise the return value
   is a string allocated with ssh_xmalloc (to be freed by the caller). */
static char *ssh_pgp_get_key_comment(SshFileBuffer *filebuf);

/* Compare two key fingerprints.  Ignore case and whitespace.
   Return TRUE if fingerprints are same. */
static Boolean ssh_pgp_fingerprint_match(const char *f1, const char *f2)
{

  SSH_ASSERT(f1 != NULL);
  SSH_ASSERT(f2 != NULL);
  for (;;)
    {
      while ((*f1 != '\0') && isspace(*f1))
        f1++;
      while ((*f2 != '\0') && isspace(*f2))
        f2++;
      if ((*f1 == '\0') && (*f2 == '\0'))
        return TRUE;
      if ((*f1 == '\0') || (*f2 == '\0'))
        return FALSE;
      if (((isalpha((int)(*f1))) ? (tolower((int)(*f1))) : ((int)(*f1))) !=
          ((isalpha((int)(*f2))) ? (tolower((int)(*f2))) : ((int)(*f2))))
        return FALSE;
      f1++;
      f2++;
    }
  /*NOTREACHED*/
}

static char *ssh_pgp_get_key_comment(SshFileBuffer *filebuf)
{
  char *r;
  SshPgpPacket current;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          SSH_DEBUG(5, ("unable to read another pgp packet"));
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_PUBKEY:
        case SSH_PGP_PACKET_TYPE_PUBSUBKEY:
        case SSH_PGP_PACKET_TYPE_SECKEY:
        case SSH_PGP_PACKET_TYPE_SECSUBKEY:
          ssh_pgp_packet_free(current);
          return NULL;

        case SSH_PGP_PACKET_TYPE_NAME:
          r = ssh_pgp_packet_name(current);
          ssh_pgp_packet_free(current);
          return r;

        default:
          ssh_pgp_packet_free(current);
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_public_key_with_name(SshFileBuffer *filebuf, 
                                          const char *name,
                                          Boolean exact,
                                          SshPgpPacket *packet,
                                          char **comment)
{
  SshPgpPacket key = NULL;
  SshPgpPacket current;
  char *key_name;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          SSH_DEBUG(5, ("unable to read another pgp packet"));
          if (key != NULL)
            ssh_pgp_packet_free(key);
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_PUBKEY:
          SSH_DEBUG(5, ("got pgp key packet"));
          if (key != NULL)
            ssh_pgp_packet_free(key);
          key = current;
          break;

        case SSH_PGP_PACKET_TYPE_NAME:
          key_name = ssh_pgp_packet_name(current);
          SSH_DEBUG(5, ("got pgp name packet \"%s\"", key_name));
          if ((key != NULL) &&
              (key_name != NULL) && 
              ((strcmp(name, key_name) == 0) ||
               ((! exact) && ssh_match_pattern(key_name, name))))
            {
              if (comment)
                *comment = key_name;
              else
                ssh_xfree(key_name);
              ssh_pgp_packet_free(current);
              *packet = key;
              return TRUE;
            }
          ssh_xfree(key_name);
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);   
          break;
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_public_key_with_key_id(SshFileBuffer *filebuf, 
                                            SshUInt32 key_id,
                                            SshPgpPacket *packet,
                                            char **comment)
{
  SshPgpPacket current;
  SshPgpPublicKey key;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          SSH_DEBUG(5, ("unable to read another pgp packet"));
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_PUBKEY:
        case SSH_PGP_PACKET_TYPE_PUBSUBKEY:
          SSH_DEBUG(5, ("got pgp key packet"));
          if (ssh_pgp_public_key_decode(current->data,
                                        current->len, 
                                        &key) > 0)
            {
              if (key->id_low == key_id)
                {
                  *packet = current;
                  if (comment)
                    {
                      char *key_comment;
                      char id_buf[16];

                      key_comment = ssh_pgp_get_key_comment(filebuf);
                      if (key_comment)
                        {
                          *comment = key_comment;
                        }
                      else
                        {
                          snprintf(id_buf, sizeof (id_buf), "0x%08lx",
                                   (unsigned long)(key->id_low));
                          *comment = ssh_xstrdup(id_buf);
                        }
                    }
                  ssh_pgp_public_key_free(key);
                  return TRUE;
                }
              else
                {
                  ssh_pgp_public_key_free(key);
                }
            }
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);
          break;
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_public_key_with_fingerprint(SshFileBuffer *filebuf, 
                                                 const char *fingerprint,
                                                 SshPgpPacket *packet,
                                                 char **comment)
{
  SshPgpPacket current;
  SshPgpPublicKey key;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_PUBKEY:
        case SSH_PGP_PACKET_TYPE_PUBSUBKEY:
          if (ssh_pgp_public_key_decode(current->data,
                                        current->len, 
                                        &key) > 0)
            {
              if (ssh_pgp_fingerprint_match(fingerprint, key->fingerprint))
                {
                  if (comment)
                    {
                      char *key_comment;
                      char id_buf[16];

                      key_comment = ssh_pgp_get_key_comment(filebuf);
                      if (key_comment)
                        {
                          *comment = key_comment;
                        }
                      else
                        {
                          snprintf(id_buf, sizeof (id_buf), "0x%08lx",
                                   (unsigned long)(key->id_low));
                          *comment = ssh_xstrdup(id_buf);
                        }
                    }
                  ssh_pgp_public_key_free(key);
                  *packet = current;
                  return TRUE;
                }
              else
                {
                  ssh_pgp_public_key_free(key);
                }
            }
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);
          break;
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_secret_key_with_name(SshFileBuffer *filebuf, 
                                          const char *name,
                                          Boolean exact,
                                          SshPgpPacket *packet,
                                          char **comment)
{
  SshPgpPacket key = NULL;
  SshPgpPacket current;
  char *key_name;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          if (key != NULL)
            ssh_pgp_packet_free(key);
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_SECKEY:
          if (key != NULL)
            ssh_pgp_packet_free(key);
          key = current;
          break;

        case SSH_PGP_PACKET_TYPE_NAME:
          key_name = ssh_pgp_packet_name(current);
          if ((key != NULL) &&
              (key_name != NULL) && 
              ((strcmp(name, key_name) == 0) ||
               ((! exact) && ssh_match_pattern(key_name, name))))
            {
              if (comment)
                *comment = key_name;
              else
                ssh_xfree(key_name);
              ssh_pgp_packet_free(current);
              *packet = key;
              return TRUE;
            }
          ssh_xfree(key_name);
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);   
          break;
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_secret_key_with_key_id(SshFileBuffer *filebuf, 
                                            SshUInt32 key_id,
                                            SshPgpPacket *packet,
                                            char **comment)
{
  SshPgpPacket current;
  SshPgpSecretKey key;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_SECKEY:
        case SSH_PGP_PACKET_TYPE_SECSUBKEY:
          if (ssh_pgp_secret_key_decode(current->data,
                                        current->len, 
                                        &key) > 0)
            {
              if (key->public_key->id_low == key_id)
                {
                  if (comment)
                    {
                      char *key_comment;
                      char id_buf[16];

                      key_comment = ssh_pgp_get_key_comment(filebuf);
                      if (key_comment)
                        {
                          *comment = key_comment;
                        }
                      else
                        {
                          snprintf(id_buf, sizeof (id_buf), "0x%08lx",
                                   (unsigned long)(key->public_key->id_low));
                          *comment = ssh_xstrdup(id_buf);
                        }
                    }
                  ssh_pgp_secret_key_free(key);
                  *packet = current;
                  return TRUE;
                }
              else
                {
                  ssh_pgp_secret_key_free(key);
                }
            }
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);
          break;
        }
    }
  /*NOTREACHED*/
}

Boolean ssh_pgp_find_secret_key_with_fingerprint(SshFileBuffer *filebuf, 
                                                 const char *fingerprint,
                                                 SshPgpPacket *packet,
                                                 char **comment)
{
  SshPgpPacket current;
  SshPgpSecretKey key;

  for (;;)
    {
      if (ssh_pgp_read_packet(filebuf, &current) == FALSE)
        {
          return FALSE;
        }
      switch (current->type)
        {
        case SSH_PGP_PACKET_TYPE_SECKEY:
        case SSH_PGP_PACKET_TYPE_SECSUBKEY:
          if (ssh_pgp_secret_key_decode(current->data,
                                        current->len, 
                                        &key) > 0)
            {
              if (ssh_pgp_fingerprint_match(fingerprint, 
                                            key->public_key->fingerprint))
                {
                  if (comment)
                    {
                      char *key_comment;
                      char id_buf[16];

                      key_comment = ssh_pgp_get_key_comment(filebuf);
                      if (key_comment)
                        {
                          *comment = key_comment;
                        }
                      else
                        {
                          snprintf(id_buf, sizeof (id_buf), "0x%08lx",
                                   (unsigned long)(key->public_key->id_low));
                          *comment = ssh_xstrdup(id_buf);
                        }
                    }
                  ssh_pgp_secret_key_free(key);
                  *packet = current;
                  return TRUE;
                }
              else
                {
                  ssh_pgp_secret_key_free(key);
                }
            }
          ssh_pgp_packet_free(current);
          break;

        default:
          ssh_pgp_packet_free(current);
          break;
        }
    }
  /*NOTREACHED*/
}

#endif /* WITH_PGP */
/* eof (pgp_keydb.c) */
