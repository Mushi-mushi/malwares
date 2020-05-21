/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/sshurl.c,v $
 *        $Author: mtr $
 *
 *        Creation          : 10:04 Jul 10 1998 kivinen
 *        Last Modification : 17:45 Jan 28 1999 kivinen
 *        Last check in     : $Date: 1999/01/29 13:10:04 $
 *        Revision number   : $Revision: 1.4 $
 *        State             : $State: Exp $
 *        Version           : 1.231
 *
 *        Description       : Library to parse urls
 */
/*
 * $Id: sshurl.c,v 1.4 1999/01/29 13:10:04 mtr Exp $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshurl.h"

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped.
 */
Boolean ssh_url_parse(const char *url, char **scheme, char **host,
                      char **port, char **username, char **password,
                      char **path)
{
  const char *p, *q, *start;

  p = url;

  if (scheme)
    *scheme = NULL;
  if (host)
    *host = NULL;
  if (port)
    *port = NULL;
  if (username)
    *username = NULL;
  if (password)
    *password = NULL;
  if (path)
    *path = NULL;

  while (isspace(*p))
    p++;

  if (!*p)
    {
      return FALSE;
    }

  start = p;
  while (isalpha(*p) || isdigit(*p) || *p == '+' || *p == '-' || *p == '.')
    p++;

  /* Check for scheme */
  if (*p == ':')
    {
      if (scheme != NULL)
        *scheme = ssh_xmemdup(start, p - start);
      p++;
      start = p;
    }

  p = start;
  /* Do we have host name part */
  if (p[0] == '/' && p[1] == '/')
    {
      start += 2;

      p = start;
      /* Check for username and password */
      while (*p && *p != '@' && *p != '/')
        p++;

      if (*p == '@')
        {
          /* User name (and possible password found) */

          q = p;
          while (q > start && *q != ':')
            q--;

          if (*q == ':')
            {
              /* Password found */
              if (username != NULL)
                *username = ssh_xmemdup(start, q - start);
              if (password != NULL)
                *password = ssh_xmemdup(q + 1, p - (q + 1));
            }
          else
            {
              /* Only username found */
              if (username != NULL)
                *username = ssh_xmemdup(start, p - start);
            }
          p++;
          start = p;
        }

      p = start;
      /* Check for host name */
      while (*p && *p != ':' && *p != '/')
        p++;

      if (host != NULL)
        *host = ssh_xmemdup(start, p - start);
      start = p;

      if (*p == ':')
        {
          start = ++p;

          while (isdigit(*p))
            p++;

          if (port != NULL)
            *port = ssh_xmemdup(start, p - start);

          start = p;
        }
    }

  if (!*p)
    {
      return TRUE;
    }

  if (*p != '/')
    {
      if (host != NULL && *host == NULL)
        *host = ssh_xstrdup(p);
      else
        if (path != NULL)
          *path = ssh_xstrdup(p);
      return FALSE;
    }
  else
    {
      if (path != NULL)
        *path = ssh_xstrdup(p + 1);
      return TRUE;
    }
}

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise. Len is the length of
 * the input url and length of the returned url is in stored in the len_out
 * if it is not NULL. The decoded url is returned even if the decoding fails.
 */
Boolean ssh_url_decode_bin(char *url, size_t len,
                           char **url_out, size_t *len_out)
{
  char *src, *dst;
  unsigned int x;
  Boolean ok = TRUE;
  size_t src_len, dst_len;

  if (url_out != NULL)
    {
      *url_out = ssh_xmemdup(url, len);
      url = *url_out;
    }

  src = url;
  src_len = len;
  dst = url;
  dst_len = 0;
  while (src_len > 0)
    {
      if (*src == '%')
        {
          if (src_len >= 3 && isxdigit(src[1]) && isxdigit(src[2]))
            {
              if (isdigit(src[1]))
                x = src[1] - '0';
              else
                x = tolower(src[1]) - 'a' + 10;
              x *= 16;

              if (isdigit(src[2]))
                x += src[2] - '0';
              else
                x += tolower(src[2]) - 'a' + 10;

              *dst++ = x;
              dst_len++;
              src += 3;
              src_len -= 3;
            }
          else
            {
              src_len--;
              dst_len++;
              *dst++ = *src++;
              ok = FALSE;
            }
        }
      else
        {
          src_len--;
          dst_len++;
          *dst++ = *src++;
        }
    }
  *dst = 0;
  if (len_out != NULL)
    *len_out = dst_len;
  return ok;
}

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise. The decoded url is
 * returned even if the decoding fails.
 */
Boolean ssh_url_decode(char *url, char **url_out)
{
  return ssh_url_decode_bin(url, strlen(url), url_out, NULL);
}

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped. This version also decodeds url %-codings.
 */
Boolean ssh_url_parse_and_decode(const char *url, char **scheme, char **host,
                                 char **port, char **username, char **password,
                                 char **path)
{
  Boolean ok;

  ok = ssh_url_parse(url, scheme, host, port, username, password, path);

  if (scheme && *scheme)
    if (!ssh_url_decode(*scheme, NULL))
      ok = FALSE;
  if (host && *host)
    if (!ssh_url_decode(*host, NULL))
      ok = FALSE;
  if (port && *port)
    if (!ssh_url_decode(*port, NULL))
      ok = FALSE;
  if (username && *username)
    if (!ssh_url_decode(*username, NULL))
      ok = FALSE;
  if (password && *password)
    if (!ssh_url_decode(*password, NULL))
      ok = FALSE;
  if (path && *path)
    if (!ssh_url_decode(*path, NULL))
      ok = FALSE;

  return ok;
}

/* Parse one key=value pair, returns TRUE if decoding was successfull, and
   inserts the decoded key value pair to the mapping.*/
Boolean ssh_url_parse_one_item(SshMapping mapping, const char *item,
                               size_t len)
{
  const char *key, *value;
  size_t key_len, value_len;
  char *decoded_key, *decoded_value, *old_value;
  size_t decoded_key_len, decoded_value_len, old_value_len;
  Boolean ok = TRUE;

  if (len == 0)
    return FALSE;
  key = item;
  value = strchr(item, '=');
  if (value - item > len)
    {
      key_len = len;
      value = item;
      value_len = 0;
    }
  else
    {
      key_len = value - key;
      value++;
      value_len = len - key_len - 1;
    }
  if (!ssh_url_decode_bin((char *) key, key_len,
                          &decoded_key, &decoded_key_len))
    ok = FALSE;
  if (!ssh_url_decode_bin((char *) value, value_len,
                          &decoded_value, &decoded_value_len))
    ok = FALSE;

  if (ssh_mapping_get_vl(mapping, decoded_key, decoded_key_len,
                         (void *) &old_value, &old_value_len))
    {
      char *p;

      /* Concatenate strings and separate items with a '\n' character.
         Make the result null terminated */
      p = ssh_xmalloc(old_value_len + decoded_value_len + 2);
      memmove(p, old_value, old_value_len);
      p[old_value_len] = '\n';
      memmove(p + old_value_len + 1, decoded_value, decoded_value_len + 1);
      decoded_value_len = old_value_len + decoded_value_len + 1;
      ssh_xfree(decoded_value);
      decoded_value = p;
    }
  ssh_mapping_put_vl(mapping, decoded_key, decoded_key_len,
                     decoded_value, decoded_value_len);
  return ok;
}

/*
 * Decode http post data which have format:
 *
 *   name=value&name=value&...&name=value
 *
 * Returns a Mapping that has all the name and value pairs stored. If
 * the same name appears more than once in the URL, the values are
 * concatenated into one string and the individual values are
 * separated with a newline character.  The function also decodes all
 * the %-encodings from the name and values after splitting them.
 *
 * Returned mapping is storing only pointers to the variable length
 * strings, and it has internal destructor, so calling
 * ssh_mapping_free will destroy it and its contents.
 *
 * Returns TRUE if everything went ok, and FALSE if there was a
 * decoding error while processing the url.
 */
Boolean ssh_url_parse_post_form(const char *url, SshMapping *mapping)
{
  const char *p, *q;
  Boolean ok = TRUE;

  *mapping = ssh_mapping_allocate_with_func(SSH_MAPPING_FL_STORE_POINTERS |
                                           SSH_MAPPING_FL_VARIABLE_LENGTH,
                                           ssh_default_hash_function,
                                           ssh_default_compare_function,
                                           ssh_default_destructor_function,
                                           0, 0);

  p = url;
  while ((q = strchr(p, '&')) != NULL)
    {
      if (!ssh_url_parse_one_item(*mapping, p, q - p))
        ok = FALSE;
      p = q + 1;
    }
  if (!ssh_url_parse_one_item(*mapping, p, strlen(p)))
    ok = FALSE;
  return ok;
}


/*
 * Decode http get url which have format:
 *
 *   /path?name=value&name=value&...&name=value
 *
 * The function returns the path in the beginning and a Mapping that
 * has all the name and value pairs stored.  If the same name appears
 * more than once in the URL, the values are concatenated into one
 * string and the individual values are separated with a newline
 * character.  The function also decodes all the %-encodings from the
 * name and values after splitting them.
 *
 * If `path' is not NULL then a mallocated copy of decoded path
 * component is stored there.
 *
 * The returned mapping is storing only pointers to the variable
 * length strings, and it has internal destructor, so calling
 * ssh_mapping_free will destroy it and its contents.
 *
 * Returns TRUE if everything went ok, and FALSE if there was a
 * decoding error while processing the url.
 */
Boolean ssh_url_parse_form(const char *url,
                           char **path,
                           size_t *path_length,
                           SshMapping *mapping)
{
  char *p;

  p = strchr(url, '?');
  if (p == NULL)
    {
      if (path != NULL)
        *path = NULL;
      if (path_length != NULL)
        path_length = 0;
      return ssh_url_parse_post_form(url, mapping);
    }
  else
    {
      Boolean ok1 = TRUE, ok2 = TRUE;

      if (path != NULL)
        ok1 = ssh_url_decode_bin((char *) url, p - url, path, path_length);
      ok2 = ssh_url_parse_post_form(p + 1, mapping);
      if (ok1 && ok2)
        return TRUE;
      return FALSE;
    }
}
