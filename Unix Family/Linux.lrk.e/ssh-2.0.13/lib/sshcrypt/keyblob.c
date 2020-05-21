/*

  keyblob.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Dec  9 23:43:46 1996 [mkojo]

  Handling the key blob.

  */

/*
 * $Id: keyblob.c,v 1.15 1999/05/04 00:14:12 kivinen Exp $
 * $Log: keyblob.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbase64.h"
#include "sshcrc32.h"
#include "sshbuffer.h"
#include "keyblob.h"
#include "sshgetput.h"

unsigned char *get_next_chars(unsigned char *src, unsigned char *dest,
                              size_t len)
{
  int max;

  max = strlen((char *) src);
  if (max == 0)
    {
      src = NULL;
    }
  else
    {
      if (max < len)
        {
          memcpy(dest, src, max + 1);
          src += max;
        }
      else
        {
          memcpy(dest, src, len);
          dest[len] = '\0';
          src += len;
        }
    }
  return src;
}

#define LEGAL_HEADER_CHAR(c) (isalnum((c)) || ((c) == '-') || ((c) == '_'))

Boolean looking_at_header(const char *s)
{
  if ((s == NULL) || (! LEGAL_HEADER_CHAR(*s)))
    return FALSE;
  while (LEGAL_HEADER_CHAR(*s))
    s++;
  if (*s != ':')
    return FALSE;
  s++;
  if ((*s != ' ') && (*s != '\t'))
    return FALSE;
  return TRUE;
}

void skip_headers(const char **s)
{
  Boolean escaped;

  escaped = FALSE;
  while (**s && (looking_at_header(*s) || escaped))
    {
      escaped = FALSE;
      while (**s && (**s != '\n'))
        {
          escaped = ((**s == '\\') || (escaped && **s == '\r'));
          (*s)++;
        }
      while (isspace(**s))
        (*s)++;
    }
}

/*
 * Read key blob from string buffer (null terminated) and convert it to
 * binary format. Returns xmallocated blob, and if blob_len, version_major,
 * version_minor, or is_public have non NULL value the length of blob,
 * major and minor version numbers of format, and whatever the blob was
 * private or public key are returned.
 */
unsigned char *ssh_key_blob_read_from_string(const char *str,
                                             size_t *blob_len,
                                             char **headers,
                                             unsigned int *version_major,
                                             unsigned int *version_minor,
                                             Boolean *is_public)
{
  unsigned char *blob, *blob2;
  const char *base64blob, *crc64blob;
  unsigned int number;
  size_t base64blob_len, crc64blob_len;
  const char *p, *compare, *again, *headers_beg, *headers_end;
  unsigned char *p2;
  Boolean public;
  SshUInt32 crc32;

  if (version_major != NULL)
    *version_major = 0;
  if (version_minor != NULL)
    *version_minor = 0;
  if (blob_len != NULL)
    *blob_len = 0;
  
  p = str;

#define SKIP_SPACE(p) \
  do { while (isspace(*(p))) (p)++; } while (0)
#define EXPECT_CHAR(p,ch) \
  do { if (*(p) != (ch)) goto error; } while (0)
#define SKIP_CHARS(p,ch) \
  do { while (*(p) == (ch) || isspace(*(p))) (p)++; } while (0)
#define MATCH_STRING(p,str) \
  do { for(; *(p) && *(str) == tolower(*(p));(str)++) { (p)++; SKIP_SPACE(p);}\
  } while (0)
#define MATCH_STRING_GOTO_ERROR(p,str) \
  do { MATCH_STRING((p),(str)); if (*(str)) goto error; } while (0)
#define READ_NUMBER(p,n) \
  do { (n) = 0; SKIP_SPACE(p); for(; isdigit(*(p)); ) \
      { (n) = ((n) * 10) + (*(p) - '0'); (p)++; SKIP_SPACE(p); } } while (0)

  SKIP_SPACE(p);
  /* Read begin line */
  EXPECT_CHAR(p, '-');
  SKIP_CHARS(p, '-');
  
  compare = "beginssh";
  MATCH_STRING_GOTO_ERROR(p, compare);
  again = p;
  compare = "public";
  MATCH_STRING(p, compare);
  if (*compare)
    {
      p = again;
      compare = "private";
      MATCH_STRING_GOTO_ERROR(p, compare);
      public = FALSE;
    }
  else
    {
      public = TRUE;
    }
  compare = "keyblock";
  MATCH_STRING_GOTO_ERROR(p, compare);
  EXPECT_CHAR(p, '-');
  SKIP_CHARS(p, '-');
  
  /* Read version line */
  compare = "version:";
  MATCH_STRING_GOTO_ERROR(p, compare);
  READ_NUMBER(p, number);
  if (version_major != NULL)
    *version_major = number;
  EXPECT_CHAR(p, '.');
  p++;
  READ_NUMBER(p, number);
  if (version_minor != NULL)
    *version_minor = number;

  /* Compat hack for 2.0a version. New version numbers MUST be numbers */
  if (*p == 'a')
    p++;

  /* Read headers */
  SKIP_SPACE(p);
  headers_beg = p;
  skip_headers(&p);
  headers_end = p;
  if ((headers_end != headers_beg) && (!(isspace(*headers_end))))
    headers_end--;
  while (isspace(*headers_end) && (headers_end > headers_beg))
    headers_end--;
  if (headers_end != headers_beg)
    headers_end++;

  /* Read data */
  SKIP_SPACE(p);
  base64blob = p;
  base64blob_len = 0;
  while(*p && *p != '=')
    p++, base64blob_len++;
  while(*p && *p == '=')
    p++, base64blob_len++;
  SKIP_SPACE(p);

  /* Read crc */
  EXPECT_CHAR(p, '=');
  crc64blob = ++p;
  crc64blob_len = 0;
  while(*p && *p != '-')
    p++, crc64blob_len++;

  /* Read end text */
  EXPECT_CHAR(p, '-');
  SKIP_CHARS(p, '-');
  compare = "endssh";
  MATCH_STRING_GOTO_ERROR(p, compare);
  if (public)
    compare = "public";
  else
    compare = "private";
  MATCH_STRING_GOTO_ERROR(p, compare);

  compare = "keyblock";
  MATCH_STRING_GOTO_ERROR(p, compare);
  EXPECT_CHAR(p, '-');
  SKIP_CHARS(p, '-');
  
  if (is_public)
    *is_public = public;
  
  blob = ssh_base64_remove_whitespace((const unsigned char *) crc64blob,
                                      crc64blob_len);
  p2 = blob;
  SKIP_CHARS(p2, '=');
  blob2 = ssh_base64_to_buf(p2, &crc64blob_len);
  ssh_xfree(blob);
  crc32 = SSH_GET_32BIT(blob2);
  ssh_xfree(blob2);
  if (crc64blob_len != 4)
    goto error;
  blob = ssh_base64_remove_whitespace((const unsigned char *) base64blob,
                                      base64blob_len);
  blob2 = ssh_base64_to_buf(blob, &base64blob_len);
  ssh_xfree(blob);
  blob = blob2;
  if (crc32_buffer(blob, base64blob_len) != crc32)
    {
      ssh_xfree(blob);
      goto error;
    }
  if (headers)
    {
      if (headers_end != headers_beg)
        {
          *headers = ssh_xmemdup(headers_beg, headers_end - headers_beg);
        }
      else
        {
          *headers = NULL;
        }
    }
  if (blob_len)
    *blob_len = base64blob_len;
  return blob;
  
error:
  if (blob_len)
    blob_len = 0;
  return NULL;
}

/*
 * Read key blob from file and convert it to binary format. Returns
 * xmallocated blob and its length. If blob_len ptr is NULL it isn't
 * returned.
 */
unsigned char *ssh_key_blob_read(FILE *fp, size_t *blob_len, char **comments)
{
  char *buffer;
  size_t len, max_len;
  unsigned char *r;

  len = 0;
  max_len = 1024;
  buffer = ssh_xmalloc(max_len);
  while (fgets(buffer + len, max_len - len, fp) != NULL)
    {
      len += strlen(buffer + len);
      if (len >= max_len)
        {
          if (len > 0xffff)
            {
              ssh_warning("ssh_key_blob_read: keyblob file too long.");
              return NULL;
            }
          max_len *= 2;
          buffer = ssh_xrealloc(buffer, max_len);
        }
    }
  r = ssh_key_blob_read_from_string(buffer, 
                                    blob_len, 
                                    comments,
                                    NULL,
                                    NULL,
                                    NULL);

  ssh_xfree(buffer);
  return r;
}

/*
 * Write blob to buffer as ascii string. Take initialized buffer and appends
 * blob there.
 */
void ssh_key_blob_write_to_buffer(SshBuffer *buffer,
                                  unsigned char *blob,
                                  size_t blob_len,
                                  const char *comments,
                                  Boolean is_public)
{
  unsigned char *base64, *new_base64;
  unsigned char line[80];
  SshUInt32 crc32;
  
  base64 = ssh_buf_to_base64(blob, blob_len);

  if (is_public)
    snprintf((char *) line, 80, "----BEGIN SSH PUBLIC KEY BLOCK----\n");
  else
    snprintf((char *) line, 80, "----BEGIN SSH PRIVATE KEY BLOCK----\n");
  
  ssh_buffer_append(buffer, line, strlen((char *) line));
  
  snprintf((char *) line, 80, "Version: %s\n", SSH_BLOB_VERSION);
  ssh_buffer_append(buffer, line, strlen((char *) line));

  snprintf((char *) line, 80, "\n");
  if (comments)
    {
      ssh_buffer_append(buffer, (unsigned char *)comments, strlen(comments));
      ssh_buffer_append(buffer, line, strlen((char *) line));
    }
  ssh_buffer_append(buffer, line, strlen((char *) line));

  new_base64 = base64;
  
  while ((new_base64 = get_next_chars(new_base64, line, 60)) != NULL)
    {
      ssh_buffer_append(buffer, line, strlen((char *) line));
      snprintf((char *) line, 80, "\n");
      ssh_buffer_append(buffer, line, strlen((char *) line));
    }

  /* Free the blob in base64. */
  ssh_xfree(base64);

  /* Compute crc of the blob */
  crc32 = crc32_buffer(blob, blob_len);
  SSH_PUT_32BIT(line, crc32);
  
  /* Compute base64 representation crc. */
  base64 = ssh_buf_to_base64(line, 4);
  
  snprintf((char *) line, 80, "=%s\n", base64);
  ssh_buffer_append(buffer, line, strlen((char *) line));

  /* Free the crc in base64. */
  ssh_xfree(base64);
  
  snprintf((char *) line, 80, "\n");
  ssh_buffer_append(buffer, line, strlen((char *) line));
  if (is_public)
    snprintf((char *) line, 80, "---END SSH PUBLIC KEY BLOCK----\n");
  else
    snprintf((char *) line, 80, "---END SSH PRIVATE KEY BLOCK----\n");
  ssh_buffer_append(buffer, line, strlen((char *) line));
}

/*
 * Write blob to file as ascii string. 
 */
void ssh_key_blob_write(FILE *fp, unsigned char *blob,
                                  size_t blob_len,
                                  const char *comments,
                                  Boolean is_public)
{
  SshBuffer buffer;
  
  ssh_buffer_init(&buffer);
  ssh_key_blob_write_to_buffer(&buffer, blob, blob_len, comments, is_public);
  fwrite(ssh_buffer_ptr(&buffer), 1, ssh_buffer_len(&buffer), fp);
  ssh_buffer_uninit(&buffer);
}
