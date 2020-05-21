/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshutil
 *        $Source: /ssh/CVS/src/lib/sshutil/sshfileio.c,v $
 *        $Author: tri $
 *
 *        Creation          : 11:03 Oct  9 1998 kivinen
 *        Last Modification : 04:32 Nov 13 1998 kivinen
 *        Last check in     : $Date: 1999/03/15 15:23:30 $
 *        Revision number   : $Revision: 1.6 $
 *        State             : $State: Exp $
 *        Version           : 1.107
 *
 *        Description       : Read and write file from and to the disk
 *                            in various formats.
 *
 *        $Log: sshfileio.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshbase64.h"

#define SSH_BUFFER_LEN 1024

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
Boolean ssh_read_file(const char *file_name,
                      unsigned char **buf,
                      size_t *buf_len)
{
  FILE *fp;
  unsigned char *tmp;
  size_t len, ret;

  /* Read the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    fp = stdin;
  else
    fp = fopen(file_name, "rb");

  if (fp == NULL)
    return FALSE;

  len = 0;
  tmp = ssh_xmalloc(SSH_BUFFER_LEN);

  /* Read the file */
  while ((ret = fread(tmp + len, 1, SSH_BUFFER_LEN, fp)) == SSH_BUFFER_LEN)
    {
      len += SSH_BUFFER_LEN;
      tmp = ssh_xrealloc(tmp, len + SSH_BUFFER_LEN);
    }

  if (ferror(fp))
    {
      if (file_name) 
        fclose(fp);
      ssh_xfree(tmp);
      return FALSE;
    }
  len += ret;
  if (file_name) 
    fclose(fp);

  *buf = tmp;
  *buf_len = len;
  return TRUE;
}

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_base64(const char *file_name, unsigned char **buf,
                             size_t *buf_len)
{
  unsigned char *tmp, *cp;
  size_t len, i, end, start, header, inside, skip;

  if (!ssh_read_file(file_name, buf, buf_len))
    return FALSE;

  tmp = *buf;
  len = *buf_len;

  /* Remove all before and after headers. */
  for (i = 0, skip = 0, end = 0, start = 0, header = 0, inside = 0;
       i < len; i++)
    {
      switch (tmp[i])
        {
        case '-':
          if (skip)
            break;
          
          if (inside)
            end = i;
          header = 1;
          inside ^= 1;
          skip = 1;
          break;
        case '\n':
        case '\r':
          if (header)
            {
              header = 0;
              if (inside)
                start = i + 1;
            }
          skip = 0;
          break;
        default:
          break;
        }
    }
  if (end == 0 && start == 0)
    {
      start = 0;
      end = len;
    }
  if (end == start)
    {
      ssh_xfree(tmp);
      return FALSE;
    }

  if (end <= start)
    {
      ssh_xfree(tmp);
      return FALSE;
    }
  
  cp = ssh_base64_remove_whitespace(tmp + start, end - start);
  *buf = ssh_base64_to_buf(cp, buf_len);
  ssh_xfree(cp);
  ssh_xfree(tmp);
  return TRUE;
}

/* Read hexl encoded file from the disk. Return mallocated buffer and the size
   of the buffer. If the reading of file failes return FALSE. If the file name
   is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_hexl(const char *file_name, unsigned char **buf,
                           size_t *buf_len)
{
  unsigned char *tmp, *p, *q;
  size_t len, i;
  int state, l;

  if (!ssh_read_file(file_name, buf, buf_len))
    return FALSE;

  tmp = *buf;
  len = *buf_len;

  *buf = ssh_xmalloc(len + 1);
  *buf_len = 0;
  
  for(state = 0, p = *buf, q = tmp; len > 0; len--, q++)
    {
      if (state == 0)
        {
          i = 0;
          l = 0;
          if (*q == ':')
            state++;
          continue;
        }
      if (state == 1)
        {
          if (isxdigit(*q))
            {
              if (isdigit(*q))
                l = (l << 4) | (*q - '0');
              else
                l = (l << 4) | (tolower(*q) - 'a' + 10);
              i++;
              if ((i & 1) == 0)
                {
                  *p++ = l;
                  (*buf_len)++;
                  l = 0;
                }
              if (i == 32)
                state++;
            }
          else
            if (q[0] == ' ' && q[1] == ' ')
              state++;
          continue;
        }
      if (*q == '\n' || *q == '\r')
        state = 0;
    }
  
  ssh_xfree(tmp);
  return TRUE;
}


/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then read from
   the stdin (":p:-" == stdin in pem encoded format). */
Boolean ssh_read_gen_file(const char *file_name,
                          unsigned char **buf,
                          size_t *buf_len)
{
  if (strlen(file_name) < 3 || file_name[0] != ':' || file_name[2] != ':')
    return ssh_read_file(file_name, buf, buf_len);
  if (file_name[1] == 'b')
    return ssh_read_file(file_name + 3, buf, buf_len);
  if (file_name[1] == 'p')
    return ssh_read_file_base64(file_name + 3, buf, buf_len);
  if (file_name[1] == 'h')
    return ssh_read_file_hexl(file_name + 3, buf, buf_len);
  ssh_warning("Unknown file format given to ssh_read_gen_file");
  return FALSE;
}


/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
Boolean ssh_write_file(const char *file_name,
                       const unsigned char *buf,
                       size_t buf_len)
{
  FILE *fp;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    fp = stdout;
  else
    fp = fopen(file_name, "wb");

  if (fp == NULL)
    return FALSE;

  if (fwrite(buf, 1, buf_len, fp) != buf_len)
    {
      if (file_name)
        fclose(fp);
      return FALSE;
    }
  if (file_name)
    fclose(fp);
  return TRUE;
}

/* Write base 64 encoded file to the disk. If the write fails retuns FALSE. If
   the file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_base64(const char *file_name,
                              const char *begin,
                              const char *end,
                              const unsigned char *buf,
                              size_t buf_len)
{
  FILE *fp;
  char *tmp;
  size_t len, i;

  tmp = (char *) ssh_buf_to_base64(buf, buf_len);
  if (tmp == NULL)
    return FALSE;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    fp = stdout;
  else
    fp = fopen(file_name, "w");

  if (fp == NULL)
    return FALSE;

  if (begin)
    if (fprintf(fp, "%s\n", begin) < 0)
      goto error;

  len = strlen(tmp);
  for (i = 0; i + 64 < len; i += 64)
    {
      if (fwrite(tmp + i, 1, 64, fp) != 64 || fprintf(fp, "\n") < 0)
        goto error;
    }
  if (fwrite(tmp + i, 1, len - i, fp) != (len - i))
    goto error;

  if (end)
    if (fprintf(fp, "\n%s\n", end) < 0)
      goto error;
  if (file_name)
    fclose(fp);
  return TRUE;
error:
  if (file_name)
    fclose(fp);
  return FALSE;
}

/* Write hexl encoded file to the disk. If the write fails retuns FALSE. If the
   file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_hexl(const char *file_name,
                            const unsigned char *buf,
                            size_t buf_len)
{
  FILE *fp;
  size_t i, j;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    fp = stdout;
  else
    fp = fopen(file_name, "w");

  if (fp == NULL)
    return FALSE;

  for(i = 0; i < buf_len; i += 16)
    {
      if (fprintf(fp, "%08x: ", i) < 0)
        goto error;
      for(j = 0; j < 16; j++)
        {
          if (i + j < buf_len)
            {
              if (fprintf(fp, "%02x", buf[i + j]) < 0)
                goto error;
            }
          else
            {
              if (fprintf(fp, "  ") < 0)
                goto error;
            }
          if ((j % 2) == 1)
            {
              if (fprintf(fp, " ") < 0)
                goto error;
            }
        }
      if (fprintf(fp, " ") < 0)
        goto error;
        
      for(j = 0; j < 16; j++)
        {
          if (i + j < buf_len)
            {
              if (isprint(buf[i + j]))
                {
                  if (fprintf(fp, "%c", buf[i + j]) < 0)
                    goto error;
                }
              else
                {
                  if (fprintf(fp, ".") < 0)
                    goto error;
                }
            }
          else
            {
              if (fprintf(fp, " ") < 0)
                goto error;
            }
        }
      if (fprintf(fp, "\n") < 0)
        goto error;
    }

  if (file_name)
    fclose(fp);
  return TRUE;
error:
  if (file_name)
    fclose(fp);
  return FALSE;
}

/* Write pem/hexl/binary file from the disk. If the write fails retuns FALSE.
   If the file name starts with :p: then assume file is pem encoded, if it
   starts with :h: then it is assumed to be hexl format, and if it starts with
   :b: then it is assumed to be binary. If no :[bph]: is given then file is
   assumed to be binary. If any other letter is given between colons then
   warning message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdout (":p:-" == stdout in pem encoded format). */
Boolean ssh_write_gen_file(const char *file_name,
                           const char *begin, 
                           const char *end, 
                           unsigned char *buf,
                           size_t buf_len)
{
  if (strlen(file_name) < 3 || file_name[0] != ':' || file_name[2] != ':')
    return ssh_write_file(file_name, buf, buf_len);
  if (file_name[1] == 'b')
    return ssh_write_file(file_name + 3, buf, buf_len);
  if (file_name[1] == 'p')
    return ssh_write_file_base64(file_name + 3, begin, end, buf, buf_len);
  if (file_name[1] == 'h')
    return ssh_write_file_hexl(file_name + 3, buf, buf_len);
  ssh_warning("Unknown file format given to ssh_read_gen_file");
  return FALSE;
}
