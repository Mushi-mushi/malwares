/*
  ssh-keygen.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  A tool for generating and manipulating private keys.
*/

/* 
 *  $Log: ssh-keygen2.c,v $
 *  $EndLog$
 */



#include "sshincludes.h"
#include "ssh2includes.h"
#include "sshuserfiles.h"
#include "sshreadline.h"
#include "readpass.h"
#include "sshuser.h"
#include "sshcrypt.h"
#include "sshcipherlist.h"
#include "ssh2pubkeyencode.h"
#include "sshgetopt.h"
#include <sys/types.h>
#include <pwd.h>

#define SSH_DEBUG_MODULE "SshKeyGen"

/* Standard (assumed) choices.. */

#ifndef KEYGEN_ASSUMED_PUBKEY_LEN
#define KEYGEN_ASSUMED_PUBKEY_LEN 1024
#endif /* KEYGEN_ASSUMED_PUBKEY_LEN */

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

/* helptext */

const char keygen_helptext[] =
  "Usage: ssh-keygen [options]\n"
  "\n"
  "Where `options' are:\n"
  " -b nnn         Specify key strength in bits (e.g. 1024)\n"
  " -t dsa         Choose the key type (only dsa available).\n"
  " -h             Print this help text.\n"
  " -e file        Edit the comment/passphrase of the key.\n"
  " -c comment     Provide the comment.\n"
  " -p passphrase  Provide passphrase.\n"
  " -P             Assume empty passphrase.\n"
  " -q             Suppress the progress indicator.\n"
  " -1             Convert a SSH 1.x key.  (not implemented)\n"
  " -i file        Load and display information on `file'.  (not implemented)\n"
  " -v             Print ssh-keygen version number.\n"
  " -r             Stir data from stdin to random pool.\n";

/* A context structure -- we don't like global variables. */

typedef struct 
{
  int keybits;
  Boolean newkey;
  Boolean convert;
  Boolean status;
  Boolean edit_key;
  Boolean read_stdin;
  
  char *keytype;
  char *keytypecommon;
  char *comment;
  char *in_filename;
  char *out_filename;
  char *passphrase;
  Boolean pass_empty;

  SshRandomState random_state;
  SshPrivateKey private_key;
  SshPublicKey public_key;
  SshUser user;

  Boolean prog_ind;
  Boolean have_prog_ind;

} KeyGenCtx;

/* mapping of common names and CryptoLib names. Common names are
   not case sensitive.

   The first entry in this list will be the preferred (standard)
   choice. */

const char *keygen_common_names[][2] = 
{
  /* Digital Signature Standard */
  { "dsa", SSH_CRYPTO_DSS },
  { "dss", SSH_CRYPTO_DSS },


  /* Last entry */
  { NULL, NULL }
};

/* allocate the context */

KeyGenCtx *keygen_init_ctx()
{
  KeyGenCtx *kgc;

  kgc = ssh_xcalloc(1, sizeof (KeyGenCtx));
  kgc->keybits = FALSE;
  kgc->newkey = FALSE;
  kgc->convert = FALSE;
  kgc->status = FALSE;
  kgc->read_stdin = FALSE;
  kgc->edit_key = FALSE;
  
  kgc->keytype = NULL;
  kgc->keytypecommon = NULL;
  kgc->comment = NULL;
  kgc->out_filename = NULL;
  kgc->in_filename = NULL;
  kgc->passphrase = NULL;
  kgc->pass_empty = FALSE;

  kgc->user = ssh_user_initialize(NULL, FALSE);  
  kgc->random_state = ssh_randseed_open(kgc->user, NULL);
  kgc->public_key = NULL;
  kgc->private_key = NULL;

  kgc->prog_ind = FALSE;
  kgc->have_prog_ind = TRUE;

  return kgc;
}

/* Zeroize and free a NULL-terminated string, assuming that the pointer
   is non-null */

void keygen_free_str(char *s)
{
  if (s == NULL)
    return;
  memset(s, 0, strlen(s));
  ssh_xfree(s);
}

/* free the context */

void keygen_free_ctx(KeyGenCtx *kgc)
{
  keygen_free_str(kgc->keytype);
  keygen_free_str(kgc->keytypecommon);
  keygen_free_str(kgc->comment);
  keygen_free_str(kgc->in_filename);
  keygen_free_str(kgc->out_filename);
  keygen_free_str(kgc->passphrase);

  if (kgc->public_key != NULL)
    ssh_public_key_free(kgc->public_key);
  if (kgc->private_key != NULL)
    ssh_private_key_free(kgc->private_key);
  ssh_randseed_update(kgc->user, kgc->random_state, NULL);
  ssh_random_free(kgc->random_state);
  if (kgc->user != NULL)
    ssh_user_free(kgc->user, FALSE);
  if (kgc->prog_ind)
    ssh_crypto_library_register_progress_func(NULL, NULL);

  memset(kgc, 0, sizeof (KeyGenCtx));
  ssh_xfree(kgc);
}


/* Ask for a passphrase twice */

char *ssh_read_passphrase_twice(char *prompt1, char *prompt2, int from_stdin)
{
  char *r1, *r2;

  for (;;)
    {
      r1 = ssh_read_passphrase(prompt1, from_stdin);
      r2 = ssh_read_passphrase(prompt2, from_stdin);

      if (strcmp(r1, r2) != 0)
        {
          keygen_free_str(r1);
          keygen_free_str(r2);
          fprintf(stderr, "Passphrases do not match.\n");
        }
      else
        break;
    }
  keygen_free_str(r2);

  return r1;
}


/* Read a string (with echo) from stdin */

char *ssh_askpass_read_stdin(char *prompt)
{
  char buf[1024], *p;

  if (prompt != NULL)
    {
      printf("%s", prompt);
      fflush(stdout);
    }
  if (fgets(buf, sizeof (buf)-1, stdin) == NULL)
    return ssh_xstrdup("");

  for(p = buf; *p >= 32 || *p < 0; p++); 
  *p = '\0';

  p = ssh_xstrdup(buf);
  memset(buf, 0, sizeof (buf));
  
  return p;
}



/* Keygen error message */

void keygen_error(KeyGenCtx *kgc, char *expl)
{
  fprintf(stderr, "\nError: %s\n", expl);
  keygen_free_ctx(kgc);
  exit(-1);
}

/* The progress indicator */

void keygen_prog_ind(SshCryptoProgressID id, unsigned int time_value,
                     void *incr)
{
  int i;

  i = *((int *) incr);
  (*((int *) incr))++;

  if (i % 13 == 0)
    {
      printf("\r %3d ", i / 13 + 1);
    } 
  else
    {
      switch( i % 4 )
        {
        case 0:   
          printf(".");
          break;
        case 1:
        case 3:
          printf("o");
          break;
        case 2:
          printf("O");
          break;
        }
    }
  fflush(stdout);
}

/* Generate a filename for the private key */

void keygen_choose_filename(KeyGenCtx *kgc)
{
  int i;
  char buf[1024], *udir;
  struct stat st;

  if (kgc->out_filename != NULL)
    return;

  if((udir = ssh_userdir(kgc->user, NULL, TRUE)) == NULL)
    {
      ssh_warning("Unable to open user ssh2 directory. "
                  "Saving to current directory.");
      udir = ssh_xstrdup(".");
    }

  for (i = 'a'; i <= 'z'; i++)
    {
      snprintf(buf, sizeof (buf), "%s/id_%s_%d_%c",
               udir, kgc->keytypecommon, kgc->keybits, i);
      if (stat(buf, &st) == 0)
        continue;
      kgc->out_filename = ssh_xstrdup(buf);
      goto done;
    }
  ssh_fatal("Could not find a suitable file name.");

done:
  ssh_xfree(udir);
}


/* Generate the key. this is done when kgc->newkey is TRUE. */

int keygen_keygen(KeyGenCtx *kgc)
{
  SshCryptoStatus code;
  char buf[1024];
  int incr;
  char *pass = NULL;
  int r = 0;

  /* Register our progress indicator. */

  incr = 0;
  if (kgc->prog_ind == FALSE && kgc->have_prog_ind == TRUE)
    {
      ssh_crypto_library_register_progress_func(keygen_prog_ind, &incr);
      kgc->prog_ind = TRUE;
    }

  printf("Generating %d-bit %s key pair\n",
         kgc->keybits,
         kgc->keytypecommon);

  if ((code = ssh_private_key_generate(kgc->random_state, 
                                       &(kgc->private_key),
                                       kgc->keytype,
                                       SSH_PKF_SIZE, kgc->keybits,
                                       SSH_PKF_END)) != SSH_CRYPTO_OK)
    {
      keygen_error(kgc, (char *) ssh_crypto_status_message(code));
    }
  printf("\nKey generated.\n");

  printf("%s\n", kgc->comment);

  /* Ok, now save the private key. */

  keygen_choose_filename(kgc);

  if ((! kgc->passphrase) || (! (*(kgc->passphrase)))) {
    if (!(kgc->pass_empty))
      {
        pass = ssh_read_passphrase_twice("Passphrase : ", 
                                         "Again      : ", 
                                         FALSE);
      }
    else
      {
        pass = ssh_xstrdup("");
      }
    keygen_free_str(kgc->passphrase);
    kgc->passphrase = pass ? pass : ssh_xstrdup("");
  }

  if (!(*(kgc->passphrase)))
    {
      ssh_warning("Key is stored with NULL passphrase.");      
    }

  if (ssh_privkey_write(kgc->user,
                        kgc->out_filename, 
                        kgc->passphrase, 
                        kgc->comment,
                        kgc->private_key, kgc->random_state, NULL))
    {
      ssh_warning("Private key not written !");
      r++;
    }
  else 
    {
      printf("Private key saved to %s\n", kgc->out_filename);
    }

  /* Save the public key */

  snprintf(buf, sizeof (buf), "%s.pub", kgc->out_filename);
  kgc->public_key = ssh_private_key_derive_public_key(kgc->private_key);
  if (kgc->public_key == NULL)
    {
      ssh_warning("Could not derive public key from private key.");
      return r + 1;
    }
  
  if (ssh_pubkey_write(kgc->user, buf, kgc->comment, kgc->public_key, NULL))
    {
      ssh_warning("Public key not written !");
      r++;
    }
  else
    {
      printf("Public key saved to %s\n", buf);
    }
  return r;
}

/* Stir in data from stdin */

void stir_stdin(KeyGenCtx *kgc)
{
  unsigned char buffer[64];
  size_t n, bytes;
  
  bytes = 0;
  
  while (!feof(stdin))
    {
      n = fread(buffer, 1, sizeof (buffer), stdin);
      if (n > 0)
        ssh_random_add_noise(kgc->random_state, buffer, n);
      bytes += n;
    }
  memset(buffer, 0, sizeof (buffer));
  
  if (kgc->have_prog_ind)
    printf("Stirred in %lu bytes.\n", (unsigned long) bytes);
}

int keygen_convert_key(KeyGenCtx *kgc)
{
  ssh_fatal("Key conversion not yet supported.");
  return -1;
}

int keygen_edit_key(KeyGenCtx *kgc)
{
  SshPrivateKey seckey = NULL;
  SshPublicKey pubkey = NULL;
  char pubfn[1024];
  char outpubfn[1024];
  char pubbu[1024];
  char secbu[1024];
  char *secfn;
  char *outsecfn;
  int ok;
  int ed;
  char *oldcomment = NULL;
  char *newcomment = NULL;
  char *newpass = NULL;

  if (!(*(kgc->in_filename))) 
    {
      ssh_warning("Invalid keyfile.");
      return 1;
    }
  else
    {
      secfn = kgc->in_filename;
      snprintf(pubfn, sizeof (pubfn), "%s.pub", secfn);
    }
  
  if (!(kgc->out_filename))
    {
      kgc->out_filename = ssh_xstrdup(kgc->in_filename);
    }

  outsecfn = kgc->out_filename;
  snprintf(outpubfn, sizeof (outpubfn), "%s.pub", outsecfn);

  snprintf(secbu, sizeof (secbu), "%s~", kgc->in_filename);
  snprintf(pubbu, sizeof (pubbu), "%s~", pubfn);
  (void)unlink(secbu);
  (void)unlink(pubbu);

  pubkey = ssh_pubkey_read(kgc->user, pubfn, &oldcomment, NULL);

  if (! pubkey)
    {
      ssh_warning("Cannot read public keyfile %s.", pubfn);
      return 1;
    }

  if (! oldcomment)
    oldcomment = ssh_xstrdup("");

  if (kgc->passphrase)
    {
      seckey = ssh_privkey_read(kgc->user, secfn, kgc->passphrase, NULL, NULL);
    }

  if (! seckey)
    {
      seckey = ssh_privkey_read(kgc->user, secfn, "", NULL, NULL);
      if (seckey)
        {
          keygen_free_str(kgc->passphrase);
          kgc->passphrase = ssh_xstrdup("");
        }
    }
    
  if (! kgc->pass_empty)
    {
      if (! seckey)
        {
          keygen_free_str(kgc->passphrase);
          printf("Passphrase needed for key \"%s\".\n", oldcomment);
          kgc->passphrase = ssh_read_passphrase("Passphrase : ", FALSE);
          if (kgc->passphrase)
            {
              seckey = ssh_privkey_read(kgc->user, secfn, kgc->passphrase, 
                                        NULL, NULL);
            }
        }
    }

  if (! seckey)
    {
      ssh_warning("Cannot read private keyfile %s.", secfn);
      return 1;
    }

  printf("Do you want to edit key \"%s\" ", oldcomment);
  if (! ssh_read_confirmation("(yes or no)? "))
    {
      printf("Key unedited and unsaved.\n");
      keygen_free_str(oldcomment);
      return 0;
    }

  ok = 0;
  ed = 0;

  while (! ok)
    {
      if (! newcomment)
        newcomment = ssh_xstrdup(oldcomment);
      printf("Your key comment is \"%s\". ", newcomment);
      if (ssh_read_confirmation("Do you want to edit it (yes or no)? "))
        {
          if (ssh_readline("New key comment: ", 
                           (unsigned char **)&newcomment, 
                           TRUE) < 0)
            {
              fprintf(stderr, "Abort!  Key unedited and unsaved.\n");
              keygen_free_str(newpass);
              keygen_free_str(newcomment);
              keygen_free_str(oldcomment);
              return 1;
            }
          putchar('\n');
        }
      if (! newpass)
        newpass = ssh_xstrdup(kgc->passphrase);
      if (! kgc->pass_empty)
        {
          if (ssh_read_confirmation("Do you want to edit passphrase (yes or no)? "))
            {
              keygen_free_str(newpass);
              newpass = ssh_read_passphrase_twice("New passphrase : ", 
                                                  "Again          : ", 
                                                  FALSE);
              if (! newpass)
                {
                  fprintf(stderr, "Abort!  Key unedited and unsaved.\n");
                  keygen_free_str(newcomment);
                  keygen_free_str(oldcomment);
                  return 0;
                }
            }
        }
      printf("Do you want to continue editing key \"%s\" ", newcomment);
      if (ssh_read_confirmation("(yes or no)? "))
        ok = 0;
      else
        ok = 1;
    }
  if ((strcmp(newpass, kgc->passphrase) == 0) &&
      (strcmp(newcomment, oldcomment) == 0))
    {
      printf("Key unedited and unsaved.\n");
      keygen_free_str(newpass);
      keygen_free_str(newcomment);
      keygen_free_str(oldcomment);
      return 0;
    }
  printf("Do you want to save key \"%s\" to file %s ", newcomment, outsecfn);
  if (! ssh_read_confirmation("(yes or no)? "))
    {
      printf("Key unsaved.\n");
      keygen_free_str(newpass);
      keygen_free_str(newcomment);
      keygen_free_str(oldcomment);
      return 0;
    }
  
  if (strcmp(outsecfn, kgc->in_filename) == 0)
    {
      if (rename(outsecfn, secbu) != 0)
        {
          ssh_warning("Unable to backup private key.");
          keygen_free_str(newpass);
          keygen_free_str(newcomment);
          keygen_free_str(oldcomment);
          fprintf(stderr, "Abort!\n");
          return 1;
        }
    }

  if (strcmp(outpubfn, pubfn) == 0)
    {
      if (rename(outpubfn, pubbu) != 0)
        {
          ssh_warning("Unable to backup private key.");
          if (strcmp(outsecfn, secfn) == 0)
            (void)rename(secbu, outsecfn);
          keygen_free_str(newpass);
          keygen_free_str(newcomment);
          keygen_free_str(oldcomment);
          fprintf(stderr, "Abort!\n");
          return 1;
        }
    }

  if (ssh_privkey_write(kgc->user,
                        outsecfn, 
                        newpass, 
                        newcomment,
                        seckey, 
                        kgc->random_state, 
                        NULL))
    {
      ssh_warning("Unable to write private key.!");
      if (strcmp(outsecfn, secfn) == 0)
        (void)rename(secbu, outsecfn);
      if (strcmp(outpubfn, pubfn) == 0)
        (void)rename(pubbu, outpubfn);
      keygen_free_str(newpass);
      keygen_free_str(newcomment);
      keygen_free_str(oldcomment);
      fprintf(stderr, "Abort!\n");
      return 1;
    }

  if (ssh_pubkey_write(kgc->user,
                       outpubfn,
                       newcomment,
                       pubkey, 
                       NULL))
    {
      ssh_warning("Unable to write public key.!");
      unlink(outsecfn);
      if (strcmp(outsecfn, secfn) == 0)
        (void)rename(secbu, outsecfn);
      if (strcmp(outpubfn, pubfn) == 0)
        (void)rename(pubbu, outpubfn);
      keygen_free_str(newpass);
      keygen_free_str(newcomment);
      keygen_free_str(oldcomment);
      fprintf(stderr, "Abort!\n");
      return 1;
    }

  keygen_free_str(newpass);
  keygen_free_str(newcomment);
  keygen_free_str(oldcomment);

  return 0;
}

/* main for ssh-keygen */

int main(int argc, char **argv)
{
  int ch, i;
  KeyGenCtx *kgc;
  struct passwd *pw;
  char *t;
  SshTime now;
  int r = 0, rr = 0;
  
  /* Initialize the context */
  kgc = keygen_init_ctx();

  /* try to find the user's home directory */

  while ((ch = ssh_getopt(argc, argv, "vhqr?P1:t:b:p:o:i:e:c:", NULL)) != EOF)
    {
      if (!ssh_optval)
        {
          printf("%s", keygen_helptext);
          keygen_free_ctx(kgc);
          exit(1);
        }
      switch (ch) 
        {
          /* -b: specify the strength of the key */

        case 'b':
          if (kgc->keybits != 0)
            keygen_error(kgc, "Multiple -b parameters");
          kgc->keybits = atoi(ssh_optarg);
          if (kgc->keybits < 128 || kgc->keybits > 0x10000)
            keygen_error(kgc, "Illegal key size.");
          break;

          /* -t: specify the key type. */
        case 't':
          /* the kgc->keytype gets the crypto library name of the alg. */
          
          if (kgc->keytype != NULL)
            keygen_error(kgc, "multiple key types specified.");

          for (i = 0; keygen_common_names[i][0] != NULL; i++)
            {
              if (strcasecmp(keygen_common_names[i][0], ssh_optarg) == 0)
                {
                  kgc->keytypecommon = ssh_xstrdup(keygen_common_names[i][0]);
                  kgc->keytype = ssh_xstrdup(keygen_common_names[i][1]);
                  break;
                }
            }
          if (keygen_common_names[i][0] == NULL)
            keygen_error(kgc, "unknown key type.");
          break;

          /* -c: Comment string. */
        case 'c':
          kgc->comment = ssh_xstrdup(ssh_optarg);
          break;

          /* -e: Edit key file. */
        case 'e':
          kgc->edit_key = TRUE;
          kgc->in_filename = ssh_xstrdup(ssh_optarg);

          /* -p: Provide passphrase. */
        case 'p':
          kgc->passphrase = ssh_xstrdup(ssh_optarg);
          break;

          /* -P: Don't provide passphrase. */
        case 'P':
          kgc->pass_empty = TRUE;
          keygen_free_str(kgc->passphrase);
          kgc->passphrase = NULL;
          break;

          /* -1: Convert a key from SSH1 format to SSH2 format. */
        case '1':
          kgc->convert = TRUE;
          kgc->in_filename = ssh_xstrdup(ssh_optarg);
          break;

          /* -o: Provide the output filename. */
        case 'o':
          kgc->out_filename = ssh_xstrdup(ssh_optarg);
          break;

          /* -v: print the version number */
        case 'v':
          printf("ssh2-keygen version " SSH2_VERSION
                 ", compiled "__DATE__".\n");
          /* XXX more stuff here possibly */ 
          keygen_free_ctx(kgc);
          exit(0);

          /* -h: print a short help text */
        case '?':
        case 'h':
          printf("%s", keygen_helptext);
          keygen_free_ctx(kgc);
          exit(0);

          /* -q: supress the progress indicator */
        case 'q':
          kgc->have_prog_ind = FALSE;
          break;

          /* -r: stir in data from stdin to the random pool */
        case 'r':
          kgc->read_stdin = TRUE;
          break;
          
          /* -i: display (all) information about a key */
        case 'i':
          ssh_fatal("-i not yet implemented XXX");
        }
    }

  
  /* Stir in random data from stdin, if requested */

  if (kgc->read_stdin)
    {
      stir_stdin(kgc);
      keygen_free_ctx(kgc);      
      return 0;
    }
        
  if (kgc->convert)
    {
      r = keygen_convert_key(kgc);
    }
  else if (kgc->edit_key)
    {
      r = keygen_edit_key(kgc);
    }
  else
    {
      kgc->newkey = TRUE;

      if (kgc->keybits == 0)
        {
          kgc->keybits = KEYGEN_ASSUMED_PUBKEY_LEN;
        }

      if (kgc->keytype == NULL)
        {
          kgc->keytypecommon = ssh_xstrdup(keygen_common_names[0][0]);
          kgc->keytype = ssh_xstrdup(keygen_common_names[0][1]);
        }

      if (kgc->comment == NULL)
        {
          char *time_str;

          pw = getpwuid(getuid());
          if (!pw)
            keygen_error(kgc, "Could not get user's password structure.");
          t = ssh_xmalloc(64);
          gethostname(t, 64);
          kgc->comment = ssh_xmalloc(256);
          now = ssh_time();
          time_str = ssh_readable_time_string(now, TRUE);
          snprintf(kgc->comment, 256, "%d-bit %s, %s@%s, %s", 
                   kgc->keybits, kgc->keytypecommon,
                   pw->pw_name, t, time_str);
          ssh_xfree(time_str);
          ssh_xfree(t);
        }

      if (ssh_optind >= argc)
        {
          /* generate single key. if no file names given, make up one. */
          if (kgc->out_filename == NULL)
            keygen_choose_filename(kgc);
          r = keygen_keygen(kgc);
        }
      else
        { 
          if (kgc->out_filename != NULL)
            keygen_keygen(kgc);

          /* iterate over additional filenames */

          for (i = ssh_optind; i < argc; i++)
            {
              if (kgc->out_filename != NULL)
                ssh_xfree(kgc->out_filename);
              kgc->out_filename = ssh_xstrdup(argv[i]);
              rr = keygen_keygen(kgc);
              if (rr != 0)
                {
                if (r == 0)
                  r = rr;
                else
                  r = -1;
                }
            }
        }
    }

  keygen_free_ctx(kgc);

  return r;
}
