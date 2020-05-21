/*

  sshcipherlist.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Canonialize comma-separated cipher lists.

*/

#include "sshincludes.h"
#include "sshcipherlist.h"
#include "ssh2pubkeyencode.h"
#include "sshcrypt.h"
#include "namelist.h"

static void ssh_cipher_list_append(char **list, char *item)
{
  char *n;
  int li, ll;

  if (*list == NULL)
    {
      *list = ssh_xstrdup(item);
      return;
    }
  if (strlen(*list) == 0)
    {
      ssh_xfree(*list);
      *list = ssh_xstrdup(item);
      return;
    }

  ll = strlen(*list);
  li = strlen(item);

  n = ssh_xmalloc(ll + li + 2);
  snprintf(n, ll + li + 2, "%s,%s", *list, item);
  ssh_xfree(*list);
  *list = n;
}

/*
   True if list `list' contains item `item'.
*/
Boolean ssh_cipher_list_contains(char *list, char *item)
{
  char *rest;
  char *current;

  rest = list;

  while ((current = ssh_name_list_get_name(rest)) != NULL)
    {
      rest += strlen(current);
      if (*rest == ',')
        rest++;
      if (strcmp(item, current) == 0)
        {
          ssh_xfree(current);
          return TRUE;
        }
      ssh_xfree(current);
      if (strlen(rest) == 0)
        break;
    }

  return FALSE;
}

/*
   Canonialize cipher name.  Unsupported algorithms are excluded
   and names of the supported ones are always replaced with the
   `native' one.
*/
char *ssh_cipher_list_canonialize(char *list)
{
  char *rest;
  char *current;
  char *canon;
  char *r;

  rest = list;
  r = ssh_xstrdup("");

  while ((current = ssh_name_list_get_name(rest)) != NULL)
    {
      rest += strlen(current);
      if (*rest == ',')
        rest++;

      canon = ssh_cipher_get_native_name(current);
      if (canon)
        {
          if (!(ssh_cipher_list_contains(r, canon)))
            {
              ssh_cipher_list_append(&r, canon);
            }
          ssh_xfree(canon);
        }
      ssh_xfree(current);
      if (strlen(rest) == 0)
        break;
    }

  return r;
}

/* 
   Return a name list that contains items in list `original'
   so that items in list `excluded' are excluded. 
*/
char *ssh_cipher_list_exclude(char *original, char *excluded)
{
  char *rest;
  char *current;
  char *r;

  rest = original;
  r = ssh_xstrdup("");

  while ((current = ssh_name_list_get_name(rest)) != NULL)
    {
      rest += strlen(current);
      if (*rest == ',')
        rest++;

      if (! ssh_cipher_list_contains(excluded, current))
        {
          ssh_cipher_list_append(&r, current);
        }
      ssh_xfree(current);
      if (strlen(rest) == 0)
        break;
    }

  return r;
}

static int ssh_public_key_supported(char *str)
{
  char *hlp;
  int r;

  hlp = ssh_name_list_intersection_public_key(str);
  if ((hlp != NULL) && (strcmp(hlp, str) == 0))
    r = 1;
  else
    r = 0;
  ssh_xfree(hlp);
  return r;
}

char *ssh_public_key_name_ssh_to_cryptolib(char *str)
{
  char *r;

  r = NULL;
  if (str == NULL)
    r = NULL;
  else if (strcmp(str, SSH_SSH_DSS) == 0)
    r = ssh_xstrdup(SSH_CRYPTO_DSS);
  else if (ssh_public_key_supported(str))
    r = ssh_xstrdup(str);

  return r;
}

char *ssh_public_key_name_cryptolib_to_ssh(char *str)
{
  char *r;

  r = NULL;
  if (str == NULL)
    return NULL;
  else if (strcmp(str, SSH_SSH_DSS) == 0)
    r = ssh_xstrdup(SSH_SSH_DSS);
  else if (strcmp(str, SSH_CRYPTO_DSS) == 0)
    r = ssh_xstrdup(SSH_SSH_DSS);

#if 0
  else if (ssh_public_key_supported(str))
    r = ssh_xstrdup(str);
#else
  else
    r = NULL;
#endif  

  return r;
}

char *ssh_hash_name_ssh_to_cryptolib(char *str)
{
  return ssh_xstrdup(str); /* These ones match (for now anyway) */
}

char *ssh_hash_name_cryptolib_to_ssh(char *str)
{
  return ssh_xstrdup(str); /* These ones match (for now anyway) */
}

char *ssh_public_key_list_canonialize(char *list)
{
  char *rest;
  char *current;
  char *canon;
  char *r;

  rest = list;
  r = ssh_xstrdup("");

  while ((current = ssh_name_list_get_name(rest)) != NULL)
    {
      rest += strlen(current);
      if (*rest == ',')
        rest++;

      canon = ssh_public_key_name_cryptolib_to_ssh(current);
      if (canon)
        {
          if (!(ssh_cipher_list_contains(r, canon)))
            {
              ssh_cipher_list_append(&r, canon);
            }
          ssh_xfree(canon);
        }
      ssh_xfree(current);
      if (strlen(rest) == 0)
        break;
    }

  return r;
}

char *ssh_hash_list_canonialize(char *list)
{
  char *rest;
  char *current;
  char *canon;
  char *r;

  rest = list;
  r = ssh_xstrdup("");

  while ((current = ssh_name_list_get_name(rest)) != NULL)
    {
      rest += strlen(current);
      if (*rest == ',')
        rest++;

      canon = ssh_hash_name_cryptolib_to_ssh(current);
      if (canon)
        {
          if (!(ssh_cipher_list_contains(r, canon)))
            {
              ssh_cipher_list_append(&r, canon);
            }
          ssh_xfree(canon);
        }
      ssh_xfree(current);
      if (strlen(rest) == 0)
        break;
    }

  return r;
}
