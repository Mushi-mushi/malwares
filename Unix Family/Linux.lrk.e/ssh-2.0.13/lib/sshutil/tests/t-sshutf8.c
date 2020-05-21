
/*

  t-sshutf8.c

  Author: Markku-Juhani Saarinen <mjos@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
                All rights reserved.

  Test routines for the character encoding routines.
  
 */

#include "sshincludes.h"
#include "../sshutf8.h"
#include "sshdebug.h"


/* run basic tests; test that everything is approximately ok */

int utf8_basic_tests(void)
{
  unsigned char test_8[1024];
  unsigned long test_16[512];
  unsigned short test_32[256];
  SshChrConv ctx;
  size_t bytes;

  /* test strings from the spec */

  const unsigned short spec_teststr_1_16nat[] = 
  { 0x0041, 0x2262, 0x0391, 0x002e };
  const unsigned char spec_teststr_1_utf8[] =
  { 0x41, 0xe2, 0x89, 0xa2, 0xce, 0x91, 0x2e };


  /* try simple usascii -> utf8 */
    
  if((ctx = ssh_charset_init(SSH_CHARSET_USASCII, SSH_CHARSET_UTF8))
     == NULL)
    ssh_fatal("failed to get context for usascii -> utf8");
  bytes = ssh_charset_convert(ctx, "foobar", 6, test_8, 1024);
  if (bytes != 6)
    ssh_fatal("usascii -> utf8 wrong size: 6 vs %d", bytes);
  if (memcmp(test_8, "foobar", 6) != 0)
    ssh_fatal("usascii -> utf8 conversion failed.");
  ssh_charset_free(ctx);


  /* try simple latin-1 -> utf8 */

 if((ctx = ssh_charset_init(SSH_CHARSET_ISO_LATIN_1, SSH_CHARSET_UTF8))
     == NULL)
    ssh_fatal("failed to get context for latin-1 -> utf8");
  bytes = ssh_charset_convert(ctx, "foobar\200\345", 8, test_8, 1024);
  if (bytes != 10)
    ssh_fatal("latin-1 -> utf8 wrong size: 10 vs %d", bytes);

  if (memcmp(test_8, "foobar\302\200\303\245", 10) != 0)
    ssh_fatal("latin-1 -> utf8 conversion failed.");
  ssh_charset_free(ctx);

  /* XXX more more more */

  return 0;
}


/* run advanced tests. */

int utf8_advanced_tests(void)
{
  /* XXX write stuff here */

  return 0;
}

/* main */

int main(int argc, char **argv)
{
  srand(ssh_time());

  utf8_basic_tests();
  ssh_debug("basic tests passed.");
  utf8_advanced_tests();
  ssh_debug("advanced tests passed.");

  return 0;
}
