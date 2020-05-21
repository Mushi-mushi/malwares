 /*

  sshuserfiles.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Simple functions that update user's files. These are not platform-dependent.

*/

#include "sshincludes.h"
#include "sshuserfiles.h"
#include "sshencode.h"
#include "ssh2pubkeyencode.h"
#include "sshuser.h"
#include "sshuserfile.h"
#include "sshconfig.h"
#include "sshbase64.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshUserFiles"

/* List of identifier strings for public key blobs. */
typedef struct Ssh2PkFormatNameListRec
{
  const char *head, *tail;
  unsigned long magic;
} Ssh2PkFormatNameList;

Ssh2PkFormatNameList ssh2_pk_format_name_list[] =
{
  { "---- BEGIN SSH2 PUBLIC KEY ----",
    "---- END SSH2 PUBLIC KEY ----", SSH_KEY_MAGIC_PUBLIC },
  { "---- BEGIN SSH2 PRIVATE KEY ----",
    "---- END SSH2 PRIVATE KEY ----", SSH_KEY_MAGIC_PRIVATE },
  { "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
    "---- END SSH2 ENCRYPTED PRIVATE KEY ----",
    SSH_KEY_MAGIC_PRIVATE_ENCRYPTED },
  { NULL, NULL, SSH_KEY_MAGIC_FAIL }
};
  
/* Miscellenous routines for ascii key format handling. */
unsigned int ssh_key_blob_match(unsigned char *buf, size_t buf_size,
                                int type,
                                size_t *ret_start,
                                size_t *ret_end)
{
  size_t i, j, start, end, keep, tmp_pos;
  char tmp[1024];

  for (i = 0, keep = 0, tmp_pos = 0, start = 0, end = 0; i < buf_size; i++)
    {
      if (buf[i] == '\n')
        {
          tmp[tmp_pos] = '\0';
          end = i;
          
          /* Try to match against the strings. */
          switch (type)
            {
            case 0:
              for (j = 0; ssh2_pk_format_name_list[j].head; j++)
                {
                  if (strcmp(ssh2_pk_format_name_list[j].head,
                             tmp) == 0)
                    {
                      *ret_start = start;
                      *ret_end   = end;
                      return ssh2_pk_format_name_list[j].magic;
                    }
                }
              break;
            case 1:
              for (j = 0; ssh2_pk_format_name_list[j].tail; j++)
                {
                  if (strcmp(ssh2_pk_format_name_list[j].tail,
                             tmp) == 0)
                    {
                      *ret_start = start;
                      *ret_end   = end;
                      return ssh2_pk_format_name_list[j].magic;
                    }
                }
              break;
            default:
              return SSH_KEY_MAGIC_FAIL;
            }
          tmp_pos = 0;
          start = i + 1;
          continue;
        }

      switch (buf[i])
        {
          /* Handle these whitespace values with some care. */
        case '\n':
        case ' ':
        case '\t':
        case '\r':
          if (tmp_pos == 0)
            {
              keep = 0;
              break;
            }
          keep = 1;
          break;
        default:
          if (keep)
            {
              tmp[tmp_pos] = ' ';
              tmp_pos++;
              keep = 0;
            }
          tmp[tmp_pos] = buf[i];
          tmp_pos++;
          break;
        }

      /* Sadly we will now just overlap? */
      if (tmp_pos >= 1024)
        tmp_pos = 0;
    }

  return SSH_KEY_MAGIC_FAIL;
}

size_t ssh_key_blob_match_keywords(unsigned char *buf, size_t len,
                                   char *keyword)
{
  size_t i;
  
  for (i = 0; i < len; i++)
    {
      /* Skip whitespace. */
      switch (buf[i])
        {
        case ' ':
        case '\n':
        case '\t':
        case '\r':
          continue;
        default:
          break;
        }
      
      if (buf[i] == keyword[0])
        {
          if (len - i < strlen(keyword))
            return 0;
          if (memcmp(&buf[i], keyword, strlen(keyword)) == 0)
            return i + strlen(keyword);
        }
      break;
    }
  return 0;
}

/* Handle the quoted string parsing. */
size_t ssh_key_blob_get_string(unsigned char *buf, size_t len,
                               char **string)
{
  unsigned int quoting, ret_quoting;
  SshBuffer buffer;
  size_t step, i, j;

  ssh_buffer_init(&buffer);
  for (i = 0, step = 0, quoting = 0, ret_quoting = 0; i < len; i++)
    {
      switch (quoting)
        {
        case 0:
          switch (buf[i])
            {
            case ' ':
            case '\n':
            case '\r':
            case '\t':
              /* Skip! */
              break;
            case '\"': /* " */
              quoting = 2;
              ret_quoting = 0;
              break;
            default:
              /* End! */
              step = i;
              goto end;
            }
          break;
        case 1:
          if (buf[i] == '\n')
            {
              for (j = 0; isspace(buf[i + j]) && i + j < len;
                   j++)
                ;
              i = i + j - 1;
            }
          quoting = ret_quoting;
          ret_quoting = 0;
          break;
        case 2:
          switch (buf[i])
            {
            case '\\':
              quoting = 1;
              ret_quoting = 2;
              break;
            case '\"': /* " */
              quoting = 0;
              ret_quoting = 0;
              break;
            default:
              ssh_buffer_append(&buffer, &buf[i], 1);
              break;
            }
        }
    }

end:
  
  /* Make a string. */
  *string = ssh_xmalloc(ssh_buffer_len(&buffer) + 1);
  memcpy(*string, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  (*string)[ssh_buffer_len(&buffer)] = '\0';
  
  ssh_buffer_uninit(&buffer);

  return step;
}

/* Handle the parsing of the single line string. */
size_t ssh_key_blob_get_line(unsigned char *buf, size_t len,
                             char **string)
{
  size_t i, step, keep;
  SshBuffer buffer;

  ssh_buffer_init(&buffer);
  for (i = 0, step = 0, keep = 0; i < len; i++)
    {
      switch (buf[i])
        {
        case '\n':
          /* End. */
          step = i;
          goto end;
        case ' ':
        case '\t':
        case '\r':
          if (ssh_buffer_len(&buffer) == 0)
            {
              keep = 0;
              break;
            }
          keep = 1;
          break;
        default:
          if (keep)
            {
              ssh_buffer_append(&buffer, (const unsigned char *)" ", 1);
              keep = 0;
            }
          ssh_buffer_append(&buffer, &buf[i], 1);
          break;
        }
    }

end:
  
  /* Make a string. */
  *string = ssh_xmalloc(ssh_buffer_len(&buffer) + 1);
  memcpy(*string, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  (*string)[ssh_buffer_len(&buffer)] = '\0';
  
  ssh_buffer_uninit(&buffer);

  return step;
}

/* This is not very smart way of doing anything. But should be sufficient
   for the first implementation. */
size_t ssh_key_blob_keywords(unsigned char *buf, size_t len,
                             char **name, char **comment)
{
  size_t pos, total, change;

  /* Initialize. */
  *name    = NULL;
  *comment = NULL;
  
  for (pos = 0, total = 0, change = 1; change;)
    {
      change = 0;
      /* Check for subject. */
      pos = ssh_key_blob_match_keywords(buf + total, len - total,
                                        "Subject:");
      if (pos)
        {
          /* Read the line. */
          total += pos;
          pos = ssh_key_blob_get_line(buf + total, len - total,
                                      name);
          if (pos == 0)
            return total;
          total += pos;

          /* Something changed. */
          change++;
        }
      
      /* Check for comment. */
      pos = ssh_key_blob_match_keywords(buf + total, len - total,
                                        "Comment:");

      if (pos)
        {
          /* Read the comment string. */
          total += pos;
          pos = ssh_key_blob_get_string(buf + total, len - total,
                                        comment);
          
          if (pos == 0)
            return total;
          
          /* Move forward again. */
          total += pos;

          /* Something changed. */
          change++;
        }
    }
  return total;
}

/* Decoding of the SSH2 ascii key blob format. */

unsigned long ssh2_key_blob_read(SshUser user, const char *fname, 
                                char **comment,
                                unsigned char **blob,
                                size_t *bloblen, void *context)
{
  unsigned char *pkeypem = NULL, *tmp, *whitened;
  char *my_name, *my_comment;
  size_t pkeylen, step, start, end, start2, end2;
  unsigned long magic, magic2;
  
  if (ssh_blob_read(user, fname, &pkeypem, &pkeylen, context))
    goto fail;

  /* Match first the heading. */
  magic = ssh_key_blob_match(pkeypem, pkeylen,
                             0, /* head */
                             &start, &end);

  if (magic == SSH_KEY_MAGIC_FAIL)
    goto fail;
  /* Match then the tail. */
  magic2 = ssh_key_blob_match(pkeypem, pkeylen,
                              1, /* tail */
                              &start2, &end2);

  if (magic2 != magic)
    goto fail;
  
  /* Check. */
  if (pkeylen - end == 0)
    goto fail;
    
  /* Read the keywords. */
  step = ssh_key_blob_keywords(pkeypem + end + 1, pkeylen - end - 1,
                               &my_name, &my_comment);

  /* XXX Ignore the name for now. We don't have any means of handling
     them nicely. */
  ssh_xfree(my_name);

  /* If comment is available pass it up. */
  if (comment)
    *comment = my_comment;
  else
    ssh_xfree(my_comment);
  
  /* Convert the remainder to a string. */
  tmp = ssh_xmalloc(start2 - end - step);
  memcpy(tmp, pkeypem + end + 1 + step, start2 - end - step - 1);

  /* Remove whitespace. */
  whitened = ssh_base64_remove_whitespace(tmp, start2 - end - step - 1);
  ssh_xfree(tmp);
  
  /* Decode the base64 blob. */
  *blob = ssh_base64_to_buf(whitened, bloblen);
  ssh_xfree(whitened);
  ssh_xfree(pkeypem);
  return magic;

fail:
  ssh_xfree(pkeypem);
  return SSH_KEY_MAGIC_FAIL;
}

/* Encoding of the SSH2 ascii key blob format. The format is
   as follows:
   
   ---- BEGIN SSH2 PUBLIC KEY ----
   Subject: login-name
   Comment: "Some explanatorial message."
   Base64 encoded blob.... =
   ---- END SSH2 PUBLIC KEY  ----

   */

void ssh_key_blob_dump_quoted_str(SshBuffer *buffer, size_t indend,
                                  const char *buf)
{
  size_t pos = indend;
  size_t i, buf_len = strlen(buf);
  ssh_buffer_append(buffer, (const unsigned char *)"\"", 1);
  pos++;
  
  for (i = 0; i < buf_len; i++)
    {
      if (pos > 0 && (pos % 70) == 0)
        {
          ssh_buffer_append(buffer, (const unsigned char *)"\\\n", 2);
          pos = 0;
        }
      ssh_buffer_append(buffer, (const unsigned char *)&buf[i], 1);
      pos++;
    }
  ssh_buffer_append(buffer, (const unsigned char *)"\"", 1);
}

void ssh_key_blob_dump_line_str(SshBuffer *buffer, const char *str)
{
  ssh_buffer_append(buffer, (const unsigned char *)str, strlen(str));
}

void ssh_key_blob_dump_str(SshBuffer *buffer, const char *str)
{
  size_t pos;
  size_t i, str_len = strlen(str);
  for (i = 0, pos = 0; i < str_len; i++)
    {
      if (pos > 0 && (pos % 70) == 0)
        {
          ssh_buffer_append(buffer, (const unsigned char *)"\n", 1);
          pos = 0;
        }
      ssh_buffer_append(buffer, (const unsigned char *)&str[i], 1);
      pos++;
    }
}

void ssh_key_blob_dump_lf(SshBuffer *buffer)
{
  ssh_buffer_append(buffer, (const unsigned char *)"\n", 1);
}

Boolean ssh2_key_blob_write(SshUser user, const char *fname, mode_t mode,
                           unsigned long magic,
                           const char *comment, const unsigned char *key,
                           size_t keylen, void *context)
{
  SshBuffer buffer;
  char *base64;
  unsigned int key_index;

  /* Translate to index. */
  switch (magic)
    {
    case SSH_KEY_MAGIC_PUBLIC:
      key_index = 0;
      break;
    case SSH_KEY_MAGIC_PRIVATE:
      key_index = 1;
      break;
    case SSH_KEY_MAGIC_PRIVATE_ENCRYPTED:
      key_index = 2;
      break;
    default:
      return FALSE;
    }

  ssh_buffer_init(&buffer);

  /* Add the head for the key. */
  ssh_key_blob_dump_line_str(&buffer,
                             ssh2_pk_format_name_list[key_index].head);
  ssh_key_blob_dump_lf(&buffer);

  /* Handle key words. */
  if (user && ssh_user_name(user))
    {
      /* Add the name. */
      ssh_key_blob_dump_line_str(&buffer, "Subject: ");
      ssh_key_blob_dump_line_str(&buffer, ssh_user_name(user));
      ssh_key_blob_dump_lf(&buffer);
    }

  if (comment)
    {
      /* Add the comment. */
      ssh_key_blob_dump_line_str(&buffer, "Comment: ");
      ssh_key_blob_dump_quoted_str(&buffer, 9, comment); 
      ssh_key_blob_dump_lf(&buffer);
    }

  /* Now add the base64 formatted stuff. */
  base64 = (char *)ssh_buf_to_base64(key, keylen);
  ssh_key_blob_dump_str(&buffer, base64);
  ssh_key_blob_dump_lf(&buffer);
  ssh_xfree(base64);

  /* Add the tail for the key. */
  ssh_key_blob_dump_line_str(&buffer,
                             ssh2_pk_format_name_list[key_index].tail);
  ssh_key_blob_dump_lf(&buffer);

  if (ssh_blob_write(user, fname, mode,
                     ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
                     context))
    {
      ssh_buffer_uninit(&buffer);
      return TRUE;
    }
  ssh_buffer_uninit(&buffer);
  return FALSE;
}

/* Creates a new random number generator, and loads the random seed file
   into the generator. */

SshRandomState ssh_randseed_open(SshUser user, SshConfig config)
{
  SshRandomState random_state;

  /* ok, allocate the random generator */
  random_state = ssh_random_allocate();

  /* Load the random seed file and mix it into the generator. */
  ssh_randseed_load(user, random_state, config);

  return random_state;
}

/* Read a public key from a file. Return NULL on failure. */

SshPublicKey ssh_pubkey_read(SshUser user, const char *fname, char **comment, 
                             void *context)
{
  unsigned char *pkeybuf;
  size_t pkeylen;
  unsigned long magic;
  SshPublicKey pubkey;

  pkeybuf = NULL;
  magic = ssh2_key_blob_read(user, fname, comment, &pkeybuf, &pkeylen, context);

  if (magic != SSH_KEY_MAGIC_PUBLIC)
    goto fail;
  pubkey = ssh_decode_pubkeyblob(pkeybuf, pkeylen);
  if (pubkey == NULL)
    goto fail;

  return pubkey;

  /* cleanup */
  
fail:
  if (pkeybuf != NULL)
    {
      memset(pkeybuf, 0, pkeylen);
      ssh_xfree(pkeybuf);
    }
  return NULL;
}

/* Write a public key to a file. Returns TRUE on error. */

Boolean ssh_pubkey_write(SshUser user, const char *fname, const char *comment, 
                         SshPublicKey key, void *context)
{
  unsigned char *pkeybuf;
  size_t pkeylen;
  Boolean ret;

  if ((pkeylen = ssh_encode_pubkeyblob(key, &pkeybuf)) == 0)
    return TRUE;

  ret = ssh2_key_blob_write(user, fname, 0644, 
                           SSH_KEY_MAGIC_PUBLIC,
                           comment, pkeybuf, pkeylen, context);
  memset(pkeybuf, 0, pkeylen);
  ssh_xfree(pkeybuf);

  return ret;
}


/* Read a private key from a file. Returns NULL on failure. */

SshPrivateKey ssh_privkey_read(SshUser user, 
                               const char *fname, const char *passphrase, 
                               char **comment, void *context)
{
  SshCryptoStatus code;
  SshPrivateKey privkey;
  unsigned char *pkeybuf;
  size_t pkeylen;
  unsigned long magic;

  pkeybuf = NULL;
  magic = ssh2_key_blob_read(user, fname, comment, &pkeybuf, &pkeylen, context);

  if (magic != SSH_KEY_MAGIC_PRIVATE && 
      magic != SSH_KEY_MAGIC_PRIVATE_ENCRYPTED)
    goto fail;
  
  switch(magic)
    {
    case SSH_KEY_MAGIC_PRIVATE:
      if ((code = ssh_private_key_import_with_passphrase(pkeybuf,
                                                         pkeylen,
                                                         "",
                                                         &privkey) 
           != SSH_CRYPTO_OK))
        {
          ssh_warning("ssh_privkey_read: %s.", 
                      ssh_crypto_status_message(code));
          goto fail;
        }
      break;

    case SSH_KEY_MAGIC_PRIVATE_ENCRYPTED:
      
      if ((code = ssh_private_key_import_with_passphrase(pkeybuf,
                                                         pkeylen,
                                                         passphrase,
                                                         &privkey) 
           != SSH_CRYPTO_OK))
        {
#if 0
          ssh_warning("ssh_privkey_read: %s.", 
                      ssh_crypto_status_message(code));
#endif
          goto fail;
        }
      break;

    default:
      goto fail;
    }

  /* cleanup */

  memset(pkeybuf, 0, pkeylen);
  ssh_xfree(pkeybuf);

  return privkey;
  
  
fail: 
  if (pkeybuf != NULL)
    {
      memset(pkeybuf, 0, pkeylen);
      ssh_xfree(pkeybuf);
    }
  return NULL;
}

/* Write a private key to a file with a passphrase. Return TRUE on error. */

Boolean ssh_privkey_write(SshUser user,
                          const char *fname, const char *passphrase,
                          const char *comment,
                          SshPrivateKey key, SshRandomState rand, 
                          void *context)
{
  unsigned char *pkeybuf;
  size_t pkeylen;
  SshCryptoStatus code;
  Boolean ret;

  if((code = ssh_private_key_export_with_passphrase(key, 
                                                    SSH_PASSPHRASE_CIPHER,
                                                    passphrase,
                                                    rand,
                                                    &pkeybuf,
                                                    &pkeylen))
     != SSH_CRYPTO_OK)
    {
      ssh_warning("ssh_privkey_write: %s.", ssh_crypto_status_message(code));
      return (int) code;
    }

  ret = ssh2_key_blob_write(user, fname, 0600, 
                           SSH_KEY_MAGIC_PRIVATE_ENCRYPTED,
                           comment, pkeybuf, pkeylen, context);
  memset(pkeybuf, 0, pkeylen);
  ssh_xfree(pkeybuf);
  
  return ret;
}

/* Generate a name string from any blob.  String consists of
   caller given string and space and sha1 hash of the blob in hex. 
   String is allocated with ssh_xmalloc. */
char *ssh_generate_name_from_blob(char *name,
                                  unsigned char *blob,
                                  size_t bloblen)
{
  SshHash hash;
  char *buf;
  unsigned char *digest;
  size_t len, namelen;
  int i;

  if (!name)
    name = "???";
  if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
      return ssh_xstrdup(name);
  namelen = strlen(name);
  ssh_hash_update(hash, blob, bloblen);
  len = ssh_hash_digest_length(hash);
  digest = ssh_xmalloc(len);
  ssh_hash_final(hash, digest);
  ssh_hash_free(hash);
  buf = ssh_xmalloc(namelen + 1 + (len * 2) + 1);
  strncpy(buf, name, namelen);
  buf[namelen] = ' ';
  for (i = 0; i < len; i++)
    snprintf(&(buf[namelen + 1 + (i * 2)]), 3, "%02x", digest[i]);
  ssh_xfree(digest);
  return buf;
}

