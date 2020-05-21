/*

t-s2k.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Test s2k.

*/
/*
 * $Id: t-s2k.c,v 1.4 1999/04/29 13:38:35 huima Exp $
 * $Log: t-s2k.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshmp.h" /* was "gmp.h" */
#include "sshcrypt.h"
#include "sshpgp.h"

static int hexnum(int c)
{
  if ((c >= '0') && (c <= '9'))
    return c - '0';
  else if ((c >= 'A') && (c <= 'F'))
    return c - 'A' + 10;
  else if ((c >= 'a') && (c <= 'f'))
    return c - 'a' + 10;
  return 0;
}

static void decode_h2b(unsigned char *buf, char *hex, int buflen)
{
  int i, l;

  memset(buf, 0, buflen);
  l = strlen(hex) / 2;
  for (i = 0; (i < l) && (i < buflen); i++)
      buf[i] = (hexnum(hex[i * 2]) << 4) | hexnum(hex[(i * 2) + 1]);
  return;
}

static void hexdump(unsigned char *buf, int buflen)
{
  int i;
  
  for (i = 0; i < buflen; i++)
    {
      printf("%02x", buf[i]);
    }
  printf("\n");
}

int main(int argc, char **argv)
{
  char *passphrase;
  int keylen;
  unsigned char *key;
  int s2k_count_byte;
  unsigned char s2k_salt[8];
  int s2k_type;
  int s2k_hash;
  int c, r;
  extern char *optarg;
  extern int optind;

  passphrase = "kukkuureset";
  keylen = 16;
  s2k_type = 0;
  s2k_hash = 1;
  s2k_count_byte = 0;
  memset(s2k_salt, 0, sizeof (s2k_salt));

  while ((c = getopt(argc, argv, "p:k:t:s:c:h:")) != -1)
    switch(c) {
    case 'p':
      passphrase = optarg;
      break;
    case 'k':
      keylen = atoi(optarg);
      break;
    case 't':
      s2k_type = atoi(optarg);
      break;
    case 's':
      decode_h2b(s2k_salt, optarg, sizeof (s2k_salt));
      break;
    case 'c':
      s2k_count_byte = atoi(optarg);
      break;
    case 'h':
      s2k_hash = atoi(optarg);
      break;
    default:
      fprintf(stderr, "Usage: ?");
      exit(1);
    }

  key = ssh_xmalloc(keylen);
  r = ssh_pgp_s2k(passphrase, 
                  s2k_type,
                  s2k_salt,
                  s2k_count_byte,
                  s2k_hash,
                  key,
                  keylen);
  if (r == 0)
    {
      fprintf(stderr, "ssh_pgp_s2k failed");
      exit(1);
    }
  hexdump(key, keylen);
  exit(0);
}

#else /* WITH_PGP */

int main()
{
  printf("No PGP support.\n");
  exit(1);
}

#endif /* WITH_PGP */

