/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/tests/t-url.c,v $
 *        $Author: mtr $
 *
 *        Creation          : 10:45 Jul 10 1998 kivinen
 *        Last Modification : 17:55 Jan 28 1999 kivinen
 *        Last check in     : $Date: 1999/01/29 13:13:38 $
 *        Revision number   : $Revision: 1.3 $
 *        State             : $State: Exp $
 *        Version           : 1.175
 *
 *        Description       : Test program for library to parse urls
 */
/*
 * $Id: t-url.c,v 1.3 1999/01/29 13:13:38 mtr Exp $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshurl.h"

typedef struct TestUrlRec {
  const char *url;
  const char *scheme;
  const char *host;
  const char *username;
  const char *password;
  const char *port;
  const char *path;
  Boolean ok;
} *TestUrl;

struct TestUrlRec tests[] = {
  { "http://www.ssh.fi/testing/host",
    "http", "www.ssh.fi", NULL, NULL, NULL, "testing/host", TRUE },
  { "ftp://kivinen:foobar@ftp.ssh.fi:21/hidden",
    "ftp", "ftp.ssh.fi", "kivinen", "foobar", "21", "hidden", TRUE },
  { "scheme://username:password@host:2222/path",
    "scheme", "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username:password@host/path",
    "scheme", "host", "username", "password", NULL, "path", TRUE },
  { "scheme://username@host:2222/path",
    "scheme", "host", "username", NULL, "2222", "path", TRUE },
  { "scheme://username:@host:2222/path",
    "scheme", "host", "username", "", "2222", "path", TRUE },
  { "scheme://:@host:2222/path",
    "scheme", "host", "", "", "2222", "path", TRUE },
  { "scheme://:password@host:2222/path",
    "scheme", "host", "", "password", "2222", "path", TRUE },
  { "scheme://host:2222/path",
    "scheme", "host", NULL, NULL, "2222", "path", TRUE },
  { "//username:password@host:2222/path",
    NULL, "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username:password@host:2222",
    "scheme", "host", "username", "password", "2222", NULL, TRUE },
  { "scheme://username:password@host",
    "scheme", "host", "username", "password", NULL, NULL, TRUE },
  { "scheme://username:password@host/",
    "scheme", "host", "username", "password", NULL, "", TRUE },
  { "scheme://host/path",
    "scheme", "host", NULL, NULL, NULL, "path", TRUE },
  { "scheme://host",
    "scheme", "host", NULL, NULL, NULL, NULL, TRUE },
  { "//host",
    NULL, "host", NULL, NULL, NULL, NULL, TRUE },
  { "host",
    NULL, "host", NULL, NULL, NULL, NULL, FALSE },
  { "/path",
    NULL, NULL, NULL, NULL, NULL, "path", TRUE },
  { "",
    NULL, NULL, NULL, NULL, NULL, NULL, FALSE },
  { "socks://muuri.ssh.fi:1080",
    "socks", "muuri.ssh.fi", NULL, NULL, "1080", NULL, TRUE },
  { "scheme://usernam%65:pas%73word@h%6Fst:2222/%70ath",
    "scheme", "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username%40host:pass%3aword@%68%6F%73%74:2222/%70ath",
    "scheme", "host", "username@host", "pass:word", "2222", "path", TRUE }
};

typedef struct TestFormItemRec {
  const char *key;
  const char *value;
} *TestFormItem;

typedef struct TestFormRec {
  const char *url;
  const char *path;
  Boolean ok;
  struct TestFormItemRec table[10];
} *TestForm;

struct TestFormRec form_tests[] = {
  { "/foo?a=b", "/foo", TRUE,
    { { "a", "b" } } },
  { "/foo?a=b&c=d", "/foo", TRUE,
    { { "a", "b" }, { "c", "d" } } },
  { "/aksjdklasjdlkasjdlkasjdkla?kukkuu=reset",
    "/aksjdklasjdlkasjdlkasjdkla", TRUE,
    { { "kukkuu", "reset" } } },
  { "!@#$%25^&*()_+][|\":%3f><,./'\\{}`1234567890-=?a=b&c=d&e=f",
    "!@#$%^&*()_+][|\":?><,./'\\{}`1234567890-=", TRUE,
    { { "a", "b" }, { "c", "d" }, { "e", "f" } } },
  { "%20%21%22?kukkuu=reset&zappa=bar", " !\"", TRUE,
    { { "kukkuu", "reset" }, { "zappa", "bar" } } },
  { " %21\"?kukk%75u=re%73et&zap%70a=b%61r", " !\"", TRUE,
    { { "kukkuu", "reset" }, { "zappa", "bar" } } },
  { "/fo%3do?kuk%3dk%75u=re%73et&zap%70a=b%61r%3dfoo", "/fo=o", TRUE,
    { { "kuk=kuu", "reset" }, { "zappa", "bar=foo" } } },
  { "/fo%26o?kuk%26k%75u=re%73et&zap%70a=b%61r%26foo", "/fo&o", TRUE,
    { { "kuk&kuu", "reset" }, { "zappa", "bar&foo" } } },
  { "/foo?name=Tero%20&name=T%20&name=Kivinen", "/foo", TRUE,
    { { "name", "Tero \nT \nKivinen" } } },
  { "/foo?na%6de=Tero%20&nam%65=T%20&n%61me=Kivinen", "/foo", TRUE,
    { { "name", "Tero \nT \nKivinen" } } },
  { "/fo%xx?a=b&c=d", "/fo%xx", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/fo%3?a=b&c=d", "/fo%3", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/fo%?a=b&c=d", "/fo%", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/foo?&a=b&c=d", "/foo", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/foo?a=b&&c=d", "/foo", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/foo?a=b&c=d&", "/foo", FALSE,
    { { "a", "b" }, { "c", "d" } } },
  { "/foo?a%xx=b&c=d", "/foo", FALSE,
    { { "a%xx", "b" }, { "c", "d" } } },
  { "/foo?a%3=b&c=d", "/foo", FALSE,
    { { "a%3", "b" }, { "c", "d" } } },
  { "/foo?a%=b&c=d", "/foo", FALSE,
    { { "a%", "b" }, { "c", "d" } } },
  { "/foo?a=b&c=%xxd", "/foo", FALSE,
    { { "a", "b" }, { "c", "%xxd" } } },
  { "/foo?a=b&c=%3qd", "/foo", FALSE,
    { { "a", "b" }, { "c", "%3qd" } } },
  { "/foo?a=b&c=%qd", "/foo", FALSE,
    { { "a", "b" }, { "c", "%qd" } } },
  { "/foo?a=b&c=d%", "/foo", FALSE,
    { { "a", "b" }, { "c", "d%" } } },
  { "/foo?a=b&c=d%xx", "/foo", FALSE,
    { { "a", "b" }, { "c", "d%xx" } } },
  { "/foo?a=b&c=d%3", "/foo", FALSE,
    { { "a", "b" }, { "c", "d%3" } } },
  { "/foo?na%6de=Tero%20&nam%65=T%20&n%61me=Kivinen&bar=zappa", "/foo", TRUE,
    { { "name", "Tero \nT \nKivinen" }, { "bar", "zappa" } } }
};

void mapping_print(SshMapping mapping)
{
  int i = 0;
  char *key, *value;
  size_t key_len, value_len;

  ssh_mapping_reset_index(mapping);
  while (ssh_mapping_get_next_vl(mapping, (void *) &key, &key_len,
                                 (void *) &value, &value_len))
    {
      fprintf(stderr, "[%d] key[%d] = `%s', value[%d] = `%s'\n",
              i++, key_len, key, value_len, value);
    }
}

int main(int argc, char **argv)
{
  int i, j;
  char *scheme, *host, *port, *username, *password, *path, *key, *value;
  size_t path_length, key_len, value_len;
  SshMapping mapping;

  for(i = 0; i < sizeof(tests) / sizeof(*tests); i++)
    {
      if (ssh_url_parse_and_decode(tests[i].url, &scheme, &host,
                                   &port, &username, &password, &path))
        {
          if (!tests[i].ok)
            ssh_fatal("ssh_url_parse returned true, even if it should have failed, url = %s", tests[i].url);
        }
      else
        {
          if (tests[i].ok)
            ssh_fatal("ssh_url_parse returned false, even if it should have succeeded, url = %s", tests[i].url);
        }
#define CHECK(s) \
      if (s == NULL && tests[i].s != NULL) \
        ssh_fatal("ssh_url_parse returned NULL for %s, it should have returned %s for url = %s", #s, tests[i].s, tests[i].url); \
      if (s != NULL && tests[i].s == NULL) \
        ssh_fatal("ssh_url_parse returned %s for %s, it should have returned NULL for url = %s", s, #s, tests[i].url); \
      if (s != NULL && strcmp(s, tests[i].s) != 0) \
        ssh_fatal("ssh_url_parse returned %s for %s, it should have returned %s for url = %s", s, #s, tests[i].s, tests[i].url);
      CHECK(scheme);
      CHECK(host);
      CHECK(port);
      CHECK(username);
      CHECK(password);
      CHECK(path);
    }
  for(i = 0; i < sizeof(form_tests) / sizeof(*form_tests); i++)
    {
      if (ssh_url_parse_form(form_tests[i].url, &path, &path_length,
                             &mapping))
        {
          if (!form_tests[i].ok)
            ssh_fatal("ssh_url_parse_form returned TRUE, should have returned FALSE, url = %s",
                      form_tests[i].url);
        }
      else
        {
          if (form_tests[i].ok)
            ssh_fatal("ssh_url_parse_form returned FALSE, should have returned TRUE, url = %s",
                      form_tests[i].url);
        }
      if (strcmp(form_tests[i].path, path) != 0)
        ssh_fatal("ssh_url_parse_form path check failed, url = %s, path = %s, should be %s",
                  form_tests[i].url, path, form_tests[i].path);
      for(j = 0; j < 10; j++)
        {
          if (form_tests[i].table[j].key == NULL ||
              form_tests[i].table[j].value == NULL)
            continue;
          if (!ssh_mapping_get_vl(mapping, form_tests[i].table[j].key,
                                  strlen(form_tests[i].table[j].key),
                                  (void *) &value, &value_len))
            {
              mapping_print(mapping);
              ssh_fatal("ssh_url_parse_form mapping check failed, cannot find key %s from the mapping, url = %s",
                        form_tests[i].table[j].key,
                        form_tests[i].url);
            }
          if (strcmp(value, form_tests[i].table[j].value) != 0)
            {
              ssh_fatal("ssh_url_parse_form mapping check failed, value for key %s from the mapping does not match, is = %s, should be = %s, url = %s",
                        form_tests[i].table[j].key,
                        value,
                        form_tests[i].table[j].value,
                        form_tests[i].url);
            }
        }

      ssh_mapping_reset_index(mapping);
      while (ssh_mapping_get_next_vl(mapping, (void *) &key, &key_len,
                                     (void *) &value, &value_len))
        {
          for(j = 0; j < 10; j++)
            {
              if (form_tests[i].table[j].key == NULL ||
                  form_tests[i].table[j].value == NULL)
                continue;
              if (strcmp(key, form_tests[i].table[j].key) == 0)
                break;
            }
          if (j == 10)
            {
              mapping_print(mapping);
              ssh_fatal("ssh_url_parse_form mapping check failed, found key %s, with value %s that should not exists, url = %s",
                        key, value, form_tests[i].url);
            }
        }
      ssh_mapping_free(mapping);
    }
  return 0;
}
