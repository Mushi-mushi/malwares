/*

t-snprintf.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 22:38:16 1996 ylo
Last modified: Thu Oct 24 22:58:56 1996 ylo

*/

#include "sshincludes.h"
#include "stdarg.h"

void test(const char *expect, const char *fmt, ...)
{
  va_list va;
  char buf[1024];

  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  if (strcmp(expect, buf) != 0)
    {
      printf("snprintf test failed, format '%s', expected '%s', got '%s'\n",
	     fmt, expect, buf);
      exit(1);
    }
}

int main(int ac, char **av)
{
  char buf[1024];
  int pass;

  for (pass = 0; pass < 10000; pass++)
    {
      snprintf(buf, sizeof(buf), "a%dl", 7);
      if (strcmp(buf, "a7l") != 0)
	{
	  printf("trivial snprintf test failed");
	  exit(1);
	}
      
      test("-124", "%d", -124);
      test(" -124", "%5d", -124);
      test("-124 ", "%-5d", -124);
      test("00124", "%05d", 124);
      test("1234567", "%5ld", 1234567L);

      test("d", "%c", 100);
      test("64", "%x", 100);
      test("0x64", "%#x", 100);
      test("0064", "%04x", 100);
      test("144", "%lo", 100L);

      test("ab", "%.2s", "abcdef");
      test("abcdef", "%2s", "abcdef");
      test("    abc", "%*.*s", 7, 3, "abcdef");
      test("   ab", "%5.2s", "abcdef");
      test("ab   ", "%-5.2s", "abcdef");

      test("1.1", "%g", 1.1);
      test("-7.4", "%lg", (double)-7.4);
    }

  return 0;
}
