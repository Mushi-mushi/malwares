/*

pgpkeysearch.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Dump contents of pgp file.

*/
/*
 * $Id: pgpkeysearch.c,v 1.2 1999/04/05 18:01:31 tri Exp $
 * $Log: pgpkeysearch.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshgetopt.h"
#include "sshpgp.h"

char *av0;

typedef enum {
  KEY_ID_NUMBER,
  KEY_ID_FINGERPRINT,
  KEY_ID_NAME
} PgpKeyIdType;

static void usage(void);

static void usage()
{
  fprintf(stderr, 
          "usage %s [-(s|p)] [-f keyfile] [-(N|F|I)] id...\n", av0);
}

int main(int argc, char **argv)
{
  int i, c;
  char *fn = NULL;
  FILE *f;
  SshUInt32 id_num;
  char *id_str;
  Boolean failed = FALSE, secret = FALSE, found;
  PgpKeyIdType id_type = KEY_ID_NAME;
  SshFileBuffer filebuf;
  SshPgpPacket packet;
  SshPgpPublicKey public_key;
  SshPgpSecretKey secret_key;

  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  while ((c = ssh_getopt(argc, argv, "spf:NFI", NULL)) != -1)
    {
      switch (c)
        {
        case 's':
          secret = TRUE;
          break;

        case 'p':
          secret = FALSE;
          break;
          
        case 'f':
          fn = ssh_optarg;
          break;

        case 'N':
          id_type = KEY_ID_NAME;
          break;
          
        case 'F':
          id_type = KEY_ID_FINGERPRINT;
          break;
          
        case 'I':
          id_type = KEY_ID_NUMBER;
          break;
          
        default:
          usage();
          exit(-1);
        }
    }
  if (fn == NULL)
    fn = secret ? "secring.pgp" : "pubring.pgp";
  
  argv += ssh_optind;
  argc -= ssh_optind;

  for (i = 0; i < argc; i++)
    {
      id_str = argv[i];
      if (id_type == KEY_ID_NUMBER)
        {
          unsigned long tmp = strtoul(id_str, NULL, 0);
          id_num = (SshUInt32)(tmp & 0xffffffff);
        }
      else
        {
          id_num = 0;
        }
      f = fopen(fn, "r");
      if (f != NULL)
        {
          ssh_file_buffer_init(&filebuf);
          if (ssh_file_buffer_attach_fileptr(&filebuf, f))
            {
              switch (id_type)
                {
                case KEY_ID_NUMBER:
                  if (secret)
                    {
                      found = ssh_pgp_find_secret_key_with_key_id(&filebuf, 
                                                                  id_num,
                                                                  &packet);
                    }
                  else
                    {
                      found = ssh_pgp_find_public_key_with_key_id(&filebuf, 
                                                                  id_num,
                                                                  &packet);
                    }
                  break;

                case KEY_ID_FINGERPRINT:
                  if (secret)
                    {
                      found = 
                        ssh_pgp_find_secret_key_with_fingerprint(&filebuf,
                                                                 id_str,
                                                                 &packet);
                    }
                  else
                    {
                      found = 
                        ssh_pgp_find_public_key_with_fingerprint(&filebuf,
                                                                 id_str,
                                                                 &packet);
                    }
                  break;

                case KEY_ID_NAME:
                  if (secret)
                    {
                      found = ssh_pgp_find_secret_key_with_name(&filebuf,
                                                                id_str,
                                                                TRUE,
                                                                &packet);
                    }
                  else
                    {
                      found = ssh_pgp_find_public_key_with_name(&filebuf,
                                                                id_str,
                                                                TRUE,
                                                                &packet);
                    }
                  break;

                default:
                  ssh_fatal("internal error");
                }

              ssh_file_buffer_detach(&filebuf);
            }
          ssh_file_buffer_uninit(&filebuf);
          fclose(f);
          if (found)
            {
              if (secret)
                {
                  if (ssh_pgp_secret_key_decode(packet->data,
                                                packet->len, 
                                                &secret_key) > 0)
                    {
                      printf("  type            = %d\n", 
                             secret_key->public_key->type);
                      printf("  generation time = 0x%08lx\n",
                             secret_key->public_key->generation_time);
                      printf("  validity time   = 0x%08lx\n",
                             secret_key->public_key->validity_time);
                      printf("  id              = HI=0x%08lx LO=0x%08lx\n",
                             secret_key->public_key->id_high, 
                             secret_key->public_key->id_low);
                      printf("  fingerprint     = %s\n", 
                             secret_key->public_key->fingerprint);
                      ssh_pgp_secret_key_free(secret_key);
                    }
                  else
                    {
                      printf("Can't decode public key packet \"%s\"\n", 
                             id_str);
                    }
                  ssh_pgp_packet_free(packet);
                }
              else
                {
                  if (ssh_pgp_public_key_decode(packet->data,
                                                packet->len, 
                                                &public_key) > 0)
                    {
                      printf("  type            = %d\n", 
                             public_key->type);
                      printf("  generation time = 0x%08lx\n",
                             public_key->generation_time);
                      printf("  validity time   = 0x%08lx\n",
                             public_key->validity_time);
                      printf("  id              = HI=0x%08lx LO=0x%08lx\n",
                             public_key->id_high, public_key->id_low);
                      printf("  fingerprint     = %s\n", 
                             public_key->fingerprint);
                      ssh_pgp_public_key_free(public_key);
                    }
                  else
                    {
                      printf("Can't decode public key packet \"%s\"\n", 
                             id_str);
                    }
                  ssh_pgp_packet_free(packet);
                }
            }
          else
            {
              printf("Can't find %s key \"%s\"\n", 
                     (secret ? "secret" : "public"), id_str);
              failed = TRUE;
            }
        }
      else
        {
          fprintf(stderr, "%s: Can't open key file \"%s\".\n", av0, fn);
          exit(1);
        }
    }
  exit(failed ? 1 : 0);
}
#else /* WITH_PGP */
int main()
{
  printf("PGP library not supported.\n");
  exit(1);
}
#endif /* WITH_PGP */
