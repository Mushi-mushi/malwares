/*

  t-cryptest.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Dec  3 16:05:36 1997 [mkojo]

  A test program for cryptolibrary. This program uses the psystem for
  parsing the configuration file.

  */

/*
 * $Id: t-cryptest.c,v 1.7 1999/04/29 13:38:22 huima Exp $
 * $Log: t-cryptest.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshpsystem.h"
#include "timeit.h"
#include "sshmp.h" /* was "gmp.h" */

#include "testsrcpath.h"

/* The PSystem definition. */

enum {
  /* Main environments. */
  TCR_HASH,
  TCR_MAC,
  TCR_CIPHER,
  TCR_RANDOM,
  TCR_PKCS,
  TCR_SECSHA,
  TCR_TIMING, 
  
  /* Variables. */
  TCR_NAME,
  TCR_KEY,
  TCR_DATA,
  TCR_DIGEST,
  TCR_LOOPS,
  TCR_IV,
  TCR_INPUT,
  TCR_OUTPUT

  /* More to be defined. */
};

typedef struct
{
  unsigned int loops;
  unsigned int flags;
} TimingInfo;

typedef struct
{
  FILE *fp;
  SshRandomState state;
} Passed;

void fhexdump(FILE *fp, char *str, unsigned char *cp, size_t len)
{
  int i;
  fprintf(fp, "%s: ", str);
  for (i = 0; i < len; i++)
    fprintf(fp, "%02x", cp[i]);
  printf("\n");
}

/* Hash */
typedef struct
{
  char *name;
  unsigned char *data;
  size_t data_len;
  unsigned char *digest;
  size_t digest_len;
  TimingInfo *t;
  Passed *s;
} HashFunctionTest;

/* Mac */
typedef struct
{
  char *name;
  unsigned char *key;
  size_t key_len;
  unsigned char *data;
  size_t data_len;
  unsigned char *digest;
  size_t digest_len;
  TimingInfo *t;
  Passed *s;
} MacFunctionTest;

/* Cipher */
typedef struct
{
  char *name;
  unsigned char *key;
  size_t key_len;
  unsigned char *iv;
  size_t iv_len;
  unsigned char *input;
  size_t input_len;
  unsigned char *output;
  size_t output_len;
  TimingInfo *t;
  Passed *s;
} CipherFunctionTest;

/* RNG */
typedef struct
{
  int dummy;
} RandomNumberTest;

/* Public Key */
typedef struct
{
  int dummy;  
} PublicKeyTest;

/* Secret Sharing */
typedef struct
{
  int dummy;
} SecretSharingTest;

/* Definition of TimingInfo */

SshPSystemVar var_timing_info[] =
{
  { "Loops", TCR_LOOPS, SSH_PSYSTEM_INTEGER },
  { NULL },
};

SSH_PSYSTEM_HANDLER(timing_info)
{
  TimingInfo *t;
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      t = ssh_xmalloc(sizeof(*t));
      t->loops = 0;
      t->flags = 0;
      *context_out = t;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      ssh_xfree(context_in);
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      *context_out = context_in;
      return TRUE;
    case SSH_PSYSTEM_OBJECT:
      t = context_in;
      switch (aptype)
        {
        case TCR_LOOPS:
          t->loops = ssh_mp_get_ui((SshInt*)data);
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}

SshPSystemEnv env_common[] =
{
  { "TimingInfo", TCR_TIMING,
    timing_info_handler,
    NULL, var_timing_info },
  { NULL }
};

/* The Hash case. */

SshPSystemVar var_hash_test[] =
{
  { "Name",   TCR_NAME,   SSH_PSYSTEM_NAME },
  { "Data",   TCR_DATA,   SSH_PSYSTEM_STRING },
  { "Digest", TCR_DIGEST, SSH_PSYSTEM_STRING },
  { NULL }
};

void hash_test_free(void *t)
{
  HashFunctionTest *h = t;
  ssh_xfree(h->name);
  ssh_xfree(h->digest);
  ssh_xfree(h->t);
  ssh_xfree(h);
}

Boolean hash_test(void *t)
{
  HashFunctionTest *h = t;
  SshHash hash;
  unsigned char *buf;
  size_t len;
  Boolean rv = FALSE;
  
  if (ssh_hash_allocate(h->name, &hash) != SSH_CRYPTO_OK)
    {
      fprintf(h->s->fp, "hash_test: hash %s is not supported\n",
              h->name);
      goto failed;
    }

  len = ssh_hash_digest_length(hash);
  if (len != h->digest_len)
    {
      fprintf(h->s->fp, "hash_test: digest length %u not equal to %u bytes\n",
              h->digest_len, len);
      fhexdump(h->s->fp, "incorrect (data)", h->digest, h->digest_len);
      ssh_hash_free(hash);
      goto failed;
    }
  
  ssh_hash_reset(hash);
  ssh_hash_update(hash, h->data, h->data_len);
  buf = ssh_xmalloc(len);
  ssh_hash_final(hash, buf);

  if (memcmp(buf, h->digest, len) != 0)
    {
      fprintf(h->s->fp, "hash_test: digest did not match!\n");
      fhexdump(h->s->fp, "computed", buf, len);
      fhexdump(h->s->fp, " correct", h->digest, len);
      ssh_hash_free(hash);
      goto failed;
    }

  if (h->t)
    {
      /* Do something XXX */
    }
  ssh_hash_free(hash);
  rv = TRUE;

failed:
  hash_test_free(t);
  return rv;
}

SSH_PSYSTEM_HANDLER(hash_test)
{
  HashFunctionTest *h;
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      h = ssh_xmalloc(sizeof(*h));
      h->name = NULL;
      h->data = NULL;
      h->digest = NULL;
      h->t = NULL;
      h->s = context_in;
      *context_out = h;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      hash_test_free(context_in);
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      /* This is where we run the tests. */
      return hash_test((HashFunctionTest*)context_in);
    case SSH_PSYSTEM_OBJECT:
      h = context_in;
      switch (aptype)
        {
        case TCR_NAME:
          h->name = data;
          return TRUE;
        case TCR_DATA:
          h->data = data;
          h->data_len = data_len;
          return TRUE;
        case TCR_DIGEST:
          h->digest = data;
          h->digest_len = data_len;
          return TRUE;
        case TCR_TIMING:
          h->t = data;
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}

SshPSystemVar var_mac_test[] =
{
  { "Name", TCR_NAME, SSH_PSYSTEM_NAME },
  { "Key",  TCR_KEY,  SSH_PSYSTEM_STRING },
  { "Data", TCR_DATA, SSH_PSYSTEM_STRING },
  { "Digest", TCR_DIGEST, SSH_PSYSTEM_STRING },
  { NULL }
};

void mac_test_free(void *t)
{
  MacFunctionTest *h = t;
  ssh_xfree(h->name);
  ssh_xfree(h->data);
  ssh_xfree(h->digest);
  ssh_xfree(h->t);
  ssh_xfree(h);
}

Boolean mac_test(void *t)
{
  MacFunctionTest *h = t;
  SshMac mac;
  Boolean rv = FALSE;
  unsigned char *buf;
  size_t len;
  
  if (ssh_mac_allocate(h->name, h->key, h->key_len, &mac) != SSH_CRYPTO_OK)
    {
      fprintf(h->s->fp, "mac_test: mac %s not supported.\n",
              h->name);
      goto failed;
    }

  len = ssh_mac_length(mac);
  if (len != h->digest_len)
    {
      fprintf(h->s->fp, "mac_test: digest length %u not equal to %u.\n",
              h->digest_len, len);
      ssh_mac_free(mac);
      goto failed;
    }
  
  ssh_mac_start(mac);
  ssh_mac_update(mac, h->data, h->data_len);

  buf = ssh_xmalloc(len);
  
  ssh_mac_final(mac, buf);

  if (memcmp(buf, h->digest, len) != 0)
    {
      fprintf(h->s->fp, "mac_test: digests did not match!\n");
      fhexdump(h->s->fp, "computed", buf, len);
      fhexdump(h->s->fp, " correct", h->digest, len);
      ssh_mac_free(mac);
      goto failed;
    }

  if (h->t)
    {
      /* XXX */
    }

  ssh_mac_free(mac);
  rv = TRUE;
  
failed:
  mac_test_free(t);
  return rv;
}

SSH_PSYSTEM_HANDLER(mac_test)
{
  MacFunctionTest *h;
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      h = ssh_xmalloc(sizeof(*h));
      h->name = NULL;
      h->key = NULL;
      h->data = NULL;
      h->digest = NULL;
      h->t = NULL;
      h->s = context_in;
      *context_out = h;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      mac_test_free(context_in);
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      /* This is where we run the tests. */
      return mac_test((MacFunctionTest*)context_in);
    case SSH_PSYSTEM_OBJECT:
      h = context_in;
      switch (aptype)
        {
        case TCR_NAME:
          h->name = data;
          return TRUE;
        case TCR_KEY:
          h->key = data;
          h->key_len = data_len;
          return TRUE;
        case TCR_DATA:
          h->data = data;
          h->data_len = data_len;
          return TRUE;
        case TCR_DIGEST:
          h->digest = data;
          h->digest_len = data_len;
          return TRUE;
        case TCR_TIMING:
          h->t = data;
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;  
}

SshPSystemVar var_cipher_test[] =
{
  { "Name",   TCR_NAME,   SSH_PSYSTEM_NAME },
  { "Key",    TCR_KEY,    SSH_PSYSTEM_STRING },
  { "IV",     TCR_IV,     SSH_PSYSTEM_STRING },
  { "Input",  TCR_INPUT,  SSH_PSYSTEM_STRING },
  { "Output", TCR_OUTPUT, SSH_PSYSTEM_STRING },
  { NULL }
};

void cipher_test_free(void *t)
{
  CipherFunctionTest *c = t;
  ssh_xfree(c->name);
  ssh_xfree(c->key);
  ssh_xfree(c->iv);
  ssh_xfree(c->input);
  ssh_xfree(c->output);
  ssh_xfree(c->t);
  ssh_xfree(c);
}

Boolean cipher_test(void *t)
{
  CipherFunctionTest *c = t;
  Boolean rv = FALSE;
  SshCipher cipher;
  unsigned char *buf;
  size_t len;

  if (ssh_cipher_allocate(c->name, c->key, c->key_len,
                          TRUE, &cipher) != SSH_CRYPTO_OK)
    {
      fprintf(c->s->fp, "cipher_test: cipher %s unsupported.\n",
              c->name);
      goto failed;
    }

  len = ssh_cipher_get_block_length(cipher);
  if (len != 1)
    {
      if (c->iv)
        {
          if (len != c->input_len || len != c->output_len || len != c->iv_len)
            {
              fprintf(c->s->fp,
                      "cipher_test: input = %u output = %u iv = %u\n"
                      "             assumed all to be %u bytes.\n",
                      c->input_len, c->output_len, c->iv_len, len);
              ssh_cipher_free(cipher);
              goto failed;
            }
          ssh_cipher_set_iv(cipher, c->iv);
        }
      else
        {
          if (len != c->input_len || len != c->output_len)
            {
              fprintf(c->s->fp,
                      "cipher_test: input = %u output = %u\n"
                      "             assumed both to be %u bytes.\n",
                      c->input_len, c->output_len, len);
              ssh_cipher_free(cipher);
              goto failed;
            }
        }
    }

  buf = ssh_xmalloc(len);
  if (ssh_cipher_transform(cipher, buf, c->input, len) != SSH_CRYPTO_OK)
    {
      fprintf(c->s->fp, "cipher_test: encryption with %s failed!\n",
              c->name);
      ssh_cipher_free(cipher);
      ssh_xfree(buf);
      goto failed;
    }

  if (memcmp(buf, c->output, len) != 0)
    {
      fprintf(c->s->fp, "cipher_test: matching failed!\n");
      fhexdump(c->s->fp, "computed", buf, len);
      fhexdump(c->s->fp, " correct", c->output, len);
      ssh_cipher_free(cipher);
      ssh_xfree(buf);
      goto failed;
    }

  if (c->t)
    {
      /* XXX */
    }

  ssh_cipher_free(cipher);
  ssh_xfree(buf);
  rv = TRUE;
failed:
  cipher_test_free(t);
  return rv;
}

SSH_PSYSTEM_HANDLER(cipher_test)
{
  CipherFunctionTest *c;
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      c = ssh_xmalloc(sizeof(*c));
      c->name = NULL;
      c->key = NULL;
      c->iv = NULL;
      c->input = NULL;
      c->output = NULL;
      c->t = NULL;
      c->s = context_in;
      *context_out = c;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      cipher_test_free(context_in);
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      return cipher_test(context_in);
    case SSH_PSYSTEM_OBJECT:
      c = context_in;
      switch (aptype)
        {
        case TCR_NAME:
          c->name = data;
          return TRUE;
        case TCR_KEY:
          c->key = data;
          c->key_len = data_len;
          return TRUE;
        case TCR_IV:
          c->iv = data;
          c->iv_len = data_len;
          return TRUE;
        case TCR_INPUT:
          c->input = data;
          c->input_len = data_len;
          return TRUE;
        case TCR_OUTPUT:
          c->output = data;
          c->output_len = data_len;
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}

SshPSystemEnv env_root[] =
{
  { "HashFunctionTest", TCR_HASH,
    hash_test_handler,
    env_common, var_hash_test },
  { "MacFunctionTest", TCR_MAC,
    mac_test_handler,
    env_common, var_mac_test },
  { "CipherFunctionTest", TCR_CIPHER,
    cipher_test_handler,
    env_common, var_cipher_test },
  /* Others not yet implemented. */
  { NULL }
};

SSH_PSYSTEM_HANDLER(root)
{
  if (list_level > 1)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      *context_out = context_in;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      *context_out = NULL;
      return TRUE;
    case SSH_PSYSTEM_FEED:
      *context_out = context_in;
      return TRUE;
    case SSH_PSYSTEM_LIST_OPEN:
    case SSH_PSYSTEM_LIST_CLOSE:
      return TRUE;
    case SSH_PSYSTEM_OBJECT:
      switch (aptype)
        {
        case TCR_HASH:
        case TCR_MAC:
        case TCR_CIPHER:
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}     

SshPSystemEnv root[] =
{
  { "root", 0,
    root_handler,
    env_root, NULL },
  { NULL }
};

int my_more(void *context, unsigned char **buf, size_t *buf_len)
{
  unsigned char *tmp = ssh_xmalloc(256);
  size_t bytes;
  
  bytes = fread(tmp, 1, 256, (FILE *)context);
  if (bytes == 0)
    {
      ssh_xfree(tmp);
      return 1;
    }
  *buf = tmp;
  *buf_len = bytes;
  return 0;
}

int main(int ac, char *av[])
{
  FILE *fp;
  void *ret;
  SshPSystemDef def;  
  Passed passed;
  SshPSystemError error;
  char *default_str = "./cryptest.desc";
  char *default_str_2 = TEST_SRC_PATH "/cryptest.desc";
  
  if (ac > 1) 
    {
      fp = fopen(av[1], "r");
    }
  else
    {
      fp = fopen(default_str, "r");
      if (fp == NULL)
        {
          fp = fopen(default_str_2, "r");
        }
    }
  if (fp == NULL)
    {
      fprintf(stderr, "no cryptest.desc to read from.\n");
      exit(1);
    }
  
  passed.fp = stderr;
  passed.state = ssh_random_allocate();
  def.root = root;
  def.feeding = &passed;
  def.more_context = fp;
  def.more = my_more;
  def.assign_operator = "=";
  ret = ssh_psystem_parse(&def, &error);
  fclose(fp);
  ssh_random_free(passed.state);
  if (error.status == SSH_PSYSTEM_OK)
    return 0;

  fprintf(stderr,
          "Error %u (at %u:%u): %s\n",
          error.status, error.line, error.pos,
          ssh_psystem_error_msg(error.status));
  return 1;
}
