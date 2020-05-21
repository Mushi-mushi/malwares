/*

pgpfiledump.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Dump contents of pgp file.

*/
/*
 * $Id: pgpfiledump.c,v 1.4 1999/04/06 10:01:35 tri Exp $
 * $Log: pgpfiledump.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshgetopt.h"
#include "sshpgp.h"

char *av0;
char *passphrase = NULL;

void pgp_file_dump(FILE *f)
{
  SshFileBuffer filebuf;
  SshPgpPacket packet;

  ssh_file_buffer_init(&filebuf);
  if (ssh_file_buffer_attach_fileptr(&filebuf, f))
    {
      while (ssh_pgp_read_packet(&filebuf, &packet))
        {
          printf("Packet type = %d (%s) length = %d\n",
                 packet->type,
                 ssh_pgp_packet_type_str(packet->type),
                 packet->len);
          switch (packet->type)
            {
            case SSH_PGP_PACKET_TYPE_ESK:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_SIG:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_CONVESK:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_1PASSSIG:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_SECKEY:
            case SSH_PGP_PACKET_TYPE_SECSUBKEY:
              {
                SshPgpSecretKey key;
                Boolean r;

                if (passphrase)
                  {
                    r = ssh_pgp_secret_key_decode_with_passphrase(packet->data,
                                                                  packet->len, 
                                                                  passphrase,
                                                                  &key);
                  }
                else
                  {
                    r = ssh_pgp_secret_key_decode(packet->data,
                                                  packet->len, 
                                                  &key);
                  }
                if (r > 0)
                  {
                    printf("  type            = %d\n", 
                           key->public_key->type);
                    printf("  generation time = 0x%08lx\n",
                           (unsigned long)key->public_key->generation_time);
                    printf("  validity time   = 0x%08lx\n",
                           (unsigned long)key->public_key->validity_time);
                    printf("  id              = HI=0x%08lx LO=0x%08lx\n",
                           (unsigned long)key->public_key->id_high, 
                           (unsigned long)key->public_key->id_low);
                    printf("  fingerprint     = %s\n", 
                           key->public_key->fingerprint);
                    if (key->key)
                      {
                        printf("key succesfully decrypted and imported\n");
                      }
                    else if (key->decryption_failed)
                      {
                        printf("unable to decrypt key\n");
                      }
                    else
                      {
                        printf("unable to import key\n");
                      }
                    ssh_pgp_secret_key_free(key);
                  }
                else
                  {
                    printf("  unable to parse public key blob\n");
                  }
              }
              break;

            case SSH_PGP_PACKET_TYPE_PUBKEY:
            case SSH_PGP_PACKET_TYPE_PUBSUBKEY:
              {
                SshPgpPublicKey key;
                
                if (ssh_pgp_public_key_decode(packet->data,
                                              packet->len, 
                                              &key) > 0)
                  {
                    printf("  type            = %d\n", 
                           key->type);
                    printf("  generation time = 0x%08lx\n",
                           (unsigned long)key->generation_time);
                    printf("  validity time   = 0x%08lx\n",
                           (unsigned long)key->validity_time);
                    printf("  id              = HI=0x%08lx LO=0x%08lx\n",
                           (unsigned long)key->id_high, 
                           (unsigned long)key->id_low);
                    printf("  fingerprint     = %s\n", 
                           key->fingerprint);
                    ssh_pgp_public_key_free(key);
                  }
                else
                  {
                    printf("  unable to parse public key blob\n");
                  }
              }
              break;

            case SSH_PGP_PACKET_TYPE_COMPRESSED:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_CONVENTIONAL:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_MARKER:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_LITERAL:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_TRUST:
              /*NOTHING*/
              break;

            case SSH_PGP_PACKET_TYPE_NAME:
              {
                char *name;

                name = ssh_pgp_packet_name(packet);
                if (name)
                  printf("  name = \"%s\"\n", name);
                else
                  printf("  unable to parse name\n");
                ssh_xfree(name);
              }
              break;

            case SSH_PGP_PACKET_TYPE_COMMENT:
              /*NOTHING*/
              break;

            default:
              /*NOTHING*/
              break;
            }
          ssh_pgp_packet_free(packet);
        }
      ssh_file_buffer_detach(&filebuf);
    }
  ssh_file_buffer_uninit(&filebuf);
  return;
}

static void usage(void);
static void usage()
{
  fprintf(stderr, "usage: %s [-p passphrase] [files...]\n", av0);
}

int main(int argc, char **argv)
{
  int i, c;
  FILE *f;
  Boolean failed = FALSE;

  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  while ((c = ssh_getopt(argc, argv, "p:", NULL)) != -1)
    {
      switch (c)
        {
        case 'p':
          passphrase = ssh_optarg;
          break;
          
        default:
          usage();
          exit(-1);
        }
    }
  argv += ssh_optind;
  argc -= ssh_optind;

  if (argc == 0)
    {
      pgp_file_dump(stdin);
    }
  else
    {
      for (i = 0; i < argc; i++)
        {
          if (strcmp(argv[i], "-") != 0)
            {
              f = fopen(argv[i], "r");
              if (f != NULL)
                {
                  pgp_file_dump(f);
                  fclose(f);
                }
              else
                {
                  fprintf(stderr, "%s: Can't open file \"%s\".\n", 
                          av0, argv[i]);
                  failed = TRUE;
                }
            }
          else
            {
              pgp_file_dump(stdin);
            }
          
        }
    }
  exit(failed ? 1 : 0);
  /*NOTREACHED*/
}

#else /* WITH_PGP */

int main()
{
  printf("PGP library not supported.\n");
  exit(1);
}

#endif /* WITH_PGP */

/* eof (pgpfiledump.c) */
