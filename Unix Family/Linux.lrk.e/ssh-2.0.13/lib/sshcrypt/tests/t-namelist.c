/*

t-namelist.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Sun Oct 27 01:13:18 1996 ylo

Modified by ylo and mkojo

BTW: Don't use the last modified string thing with CVS its annoying. 

*/

#include "sshincludes.h"
#include "namelist.h"

void test(const char *src1, const char *src2, const char *expect)
{
  char *buf;

  buf = ssh_name_list_intersection(src1, src2);
  if (strcmp(buf, expect) != 0)
    ssh_fatal("intersection failed: '%.100s' and '%.100s' yields '%.100s', expected '%.100s'",
	  src1, src2, buf, expect);

  ssh_xfree(buf);
}

#define TA(type,src,expect) \
  buf = ssh_name_list_intersection_##type(src); \
  if (strcmp(buf, expect) != 0) \
    ssh_fatal("%.100s '%.100s' yields '%.100s', expected '%.100s'", \
	  #type, src, buf, expect);  \
  ssh_xfree(buf);

int main(int ac, char **av)
{
  char *buf;

  int pass;

  printf("\nNamelist tests\n");
  
  for (pass = 0; pass < 1000; pass++)
    {
      printf("Pass %d\r", pass);
      fflush(stdout);
      test("", "", "");
      test("a", "", "");
      test("", "a", "");
      test("a", "a", "a");
      test("a", "b", "");
      test("a,c,e", "b,d,f", "");
      test("aa,cc,ee", "a,c,e", "");
      test("aa,ee,cc", "cc,ee,aa", "aa,ee,cc");
      test("des-cbc,3des-cbc,blowfish-cbc", "des-cbc,zap-foo,blowfish",
	   "des-cbc");
      test("foo@zappa", "foo", "");
      test("foo@zappa", "bar@zappa", "");
      test("b,foo@zappa.com,a", "c,d,foo@zappa.com,e@f", "foo@zappa.com");
      test("foo-cbc@test.com.fi", "foo-cbc@test.com.fi",
	   "foo-cbc@test.com.fi");

      /* XXX */
      test("a,b,a", "b,a,b", "a,b,a");
      test("a,b", "b,a,b", "a,b");
      
      test("a{a,b}", "a{b}", "a{b}");
      test("a{a{a,b},b{a,b},c{a,b}}", "a{a{c,d},b{b}}", "a{b{b}}");
      
      /* Super teds. */
      test("dl-modp{sign{dsa-nist-sha1,dsa-iso9796-sha1},"
	   "encrypt{elgamal-no-no}}", "ec-modp{sign{dsa-no-sha1},"
	   "encrypt{elgamal-no-no}},dl-modp{sign{dsa-iso9796-sha1},"
	   "encrypt{elgamal-random-no}}",
	   "dl-modp{sign{dsa-iso9796-sha1}}");

      TA(cipher, "des-foobar,none", "none");
      TA(cipher, "des-cbc,des-cfb,des-ecb", "des-cbc,des-cfb,des-ecb");
      TA(cipher, "des-cbc@foo.com", "");
      TA(public_key, "barfoo@ssh.fi", "");
      TA(mac, "hmac-md5,hmac-sha1,none,barz,fooz@ssh.fi",
	 "hmac-md5,hmac-sha1,none");
      TA(hash, "foo,bar,md5,baz,sha1", "md5,sha1");
      TA(compression, "foo,bar,none,zlib,baz", "none,zlib");
    }
  printf("\n");
  return 0;
}
