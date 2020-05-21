/*

t-encode.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Tests for the ssh_encode/decode functions.
  - tests encoding / decoding all data types (test_encode)
  - tests encoding empty buffer for all data types (test_empty_decode)
  - tests decoding random garbage for all data types (test_random_decode)
  - tests all functions for at least some arguments (test_functions)

*/

#include "sshincludes.h"
#include "sshencode.h"

SshBuffer *buffer;

/* This encodes data into a buffer using the given format, and compares the
   result against the expected value.  This also checks that data at the
   beginning of the buffer is not altered. */

void encode_case(const char *name, const char *expect,
                 size_t expect_len, ...)
{
  size_t len, i, bytes;
  unsigned char ch, *cp;
  va_list va;
  
  ssh_buffer_clear(buffer);
  len = rand() % 100;
  ch = rand();
  for (i = 0; i < len; i++)
    ssh_buffer_append(buffer, &ch, 1);

  va_start(va, expect_len);
  bytes = ssh_encode_va(buffer, va);
  if (bytes != expect_len || ssh_buffer_len(buffer) != len + expect_len)
    ssh_fatal("test_encode: %s: unexpected length %d vs. %d",
              name, bytes, len + expect_len);
  cp = ssh_buffer_ptr(buffer);
  if (memcmp(expect, cp + len, expect_len) != 0)
    ssh_fatal("test_encode: %s: mismatch", name);
  for (i = 0; i < len; i++)
    if (cp[i] != ch)
      ssh_fatal("test_encode: %s: beginning corrupted", name);
  ssh_buffer_consume(buffer, len);
}

void decode_case_str(SshEncodingFormat fmt, const char *value, size_t valuelen)
{
  unsigned char *cp;
  size_t len, bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_str: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &cp, &len, SSH_FORMAT_END))
    ssh_fatal("decode_case_str: bad returned len");
  if (len != valuelen || memcmp(cp, value, len) != 0)
    ssh_fatal("decode_case_str: bad cmp");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_str: data left");
  if (cp[len] != 0)
    ssh_fatal("decode_case_str: not null terminated");
  ssh_xfree(cp);
}

void decode_case_int(SshEncodingFormat fmt, unsigned int value)
{
  unsigned long lv;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_int: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &lv, SSH_FORMAT_END))
    ssh_fatal("decode_case_int: bad returned len");
  if (lv != value)
    ssh_fatal("decode_case_int: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_int: data left");
}

void decode_case_bool(SshEncodingFormat fmt, Boolean value)
{
  Boolean bool;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_bool: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &bool, SSH_FORMAT_END))
    ssh_fatal("decode_case_bool: bad returned len");
  if (bool != value)
    ssh_fatal("decode_case_bool: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_bool: data left");
}

void decode_case_char(SshEncodingFormat fmt, unsigned char value)
{
  unsigned int ch;
  size_t bytes;

  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, SSH_FORMAT_END))
    ssh_fatal("decode_case_char: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, &ch, SSH_FORMAT_END))
    ssh_fatal("decode_case_char: bad returned len");
  if (ch != value)
    ssh_fatal("decode_case_char: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_char: data left");
}

void decode_case_data(SshEncodingFormat fmt, const char *value, size_t valuelen)
{
  char buf[1024];
  size_t bytes;

  assert(valuelen < sizeof(buf));
  bytes = ssh_buffer_len(buffer);
  if (bytes != ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                                      fmt, NULL, valuelen, SSH_FORMAT_END))
    ssh_fatal("decode_case_data: NULL decode bad len");
  if (bytes != ssh_decode_buffer(buffer, fmt, buf, valuelen,
                                       SSH_FORMAT_END))
    ssh_fatal("decode_case_data: bad returned len");
  if (memcmp(buf, value, valuelen) != 0)
    ssh_fatal("decode_case_data: bad value");
  if (ssh_buffer_len(buffer) > 0)
    ssh_fatal("decode_case_data: data left");
}

void test_encode(void)
{
  encode_case("vlint32_str empty", "\0", 1,
              SSH_FORMAT_VLINT32_STR, "", 0, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_VLINT32_STR, "", 0);
  encode_case("vlint32_str empty", "\0", 1,
              SSH_FORMAT_VLINT32_STR, NULL, 0, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_VLINT32_STR, "", 0);
  encode_case("vlint32_str 1", "\1A", 2,
              SSH_FORMAT_VLINT32_STR, "ABC", 1, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_VLINT32_STR, "A", 1);
  encode_case("vlint32_str null", "\7foo\0bar", 8,
              SSH_FORMAT_VLINT32_STR, "foo\0bar", 7, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_VLINT32_STR, "foo\0bar", 7);
  encode_case("vlint32_str 65", "\100\101XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 67,
              SSH_FORMAT_VLINT32_STR, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXABC", 65, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_VLINT32_STR, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXABC", 65);
  encode_case("uint32_str 0", "\0\0\0\0", 4,
              SSH_FORMAT_UINT32_STR, NULL, 0, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "", 0);
  encode_case("uint32_str 0", "\0\0\0\0", 4,
              SSH_FORMAT_UINT32_STR, "ABC", 0, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "", 0);
  encode_case("uint32_str 5", "\0\0\0\5ABCDE", 9,
              SSH_FORMAT_UINT32_STR, "ABCDEFGHIJK", 5, SSH_FORMAT_END);
  decode_case_str(SSH_FORMAT_UINT32_STR, "ABCDE", 5);
  encode_case("vlint32 0", "\0", 1,
              SSH_FORMAT_VLINT32, (SshUInt32) 0, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 0);
  encode_case("vlint32 63", "\77", 1,
              SSH_FORMAT_VLINT32, (SshUInt32) 63, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 63);
  encode_case("vlint32 64", "\100\100", 2,
              SSH_FORMAT_VLINT32, (SshUInt32) 64, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 64);
  encode_case("vlint32 255", "\100\377", 2,
              SSH_FORMAT_VLINT32, (SshUInt32) 255, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 255);
  encode_case("vlint32 256", "\101\0", 2,
              SSH_FORMAT_VLINT32, (SshUInt32) 256, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 256);
  encode_case("vlint32 16383", "\177\377", 2,
              SSH_FORMAT_VLINT32, (SshUInt32) 16383, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 16383);
  encode_case("vlint32 16384", "\200\100\0", 3,
              SSH_FORMAT_VLINT32, (SshUInt32) 16384, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 16384);
  encode_case("vlint32 4194303", "\277\377\377", 3,
              SSH_FORMAT_VLINT32, (SshUInt32) 4194303, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 4194303);
  encode_case("vlint32 4194304", "\300\0\100\0\0", 5,
              SSH_FORMAT_VLINT32, (SshUInt32) 4194304, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 4194304);
  encode_case("vlint32 2^32-1", "\300\377\377\377\377", 5,
              SSH_FORMAT_VLINT32, (SshUInt32) 0xffffffff, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_VLINT32, (SshUInt32) 0xffffffff);
  encode_case("uint32 0x12345678", "\22\64\126\170", 4,
              SSH_FORMAT_UINT32, (SshUInt32) 0x12345678, SSH_FORMAT_END);
  decode_case_int(SSH_FORMAT_UINT32, (SshUInt32) 0x12345678);
  encode_case("boolean TRUE", "\0", 1,
              SSH_FORMAT_BOOLEAN, FALSE, SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, FALSE);
  encode_case("boolean TRUE", "\1", 1,
              SSH_FORMAT_BOOLEAN, TRUE, SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, TRUE);
  encode_case("boolean 0xff", "\1", 1,
              SSH_FORMAT_BOOLEAN, 0xff, SSH_FORMAT_END);
  decode_case_bool(SSH_FORMAT_BOOLEAN, TRUE);
  /* XXX mp tests */
  encode_case("char 0x12", "\22", 1,
              SSH_FORMAT_CHAR, (unsigned int) 0x12, SSH_FORMAT_END);
  decode_case_char(SSH_FORMAT_CHAR, (unsigned int) 0x12);
  encode_case("char 0xee", "\356", 1,
              SSH_FORMAT_CHAR, (unsigned int) 0xee, SSH_FORMAT_END);
  decode_case_char(SSH_FORMAT_CHAR, (unsigned int) 0xee);
  encode_case("data foo\\0bar", "foo\0bar", 7,
              SSH_FORMAT_DATA, "foo\0bar", 7, SSH_FORMAT_END);
  decode_case_data(SSH_FORMAT_DATA, "foo\0bar", 7);
  encode_case("nothing", "", 0, SSH_FORMAT_END);
  if (ssh_buffer_len(buffer) != 0)
    ssh_fatal("``nothing'' encoded to non-empty");
}

void test_empty_decode(void)
{
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_VLINT32_STR, NULL, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_UINT32_STR, NULL, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_VLINT32, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_UINT32, NULL, 
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_CHAR, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_BOOLEAN, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *) "", 0,
                       SSH_FORMAT_DATA, NULL, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
  if (ssh_decode_array((const unsigned char *)"", 0,
                       SSH_FORMAT_MP_INT, NULL,
                       SSH_FORMAT_END) != 0)
    ssh_fatal("test_empty_decode failed");
}

void test_random_decode(void)
{
  unsigned char buf[16];
  size_t i;

  for (i = 0; i < sizeof(buf); i++)
    buf[i] = rand();
  
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_VLINT32_STR, NULL, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_UINT32_STR, NULL, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_VLINT32, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_UINT32, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_CHAR, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_BOOLEAN, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_DATA, NULL, NULL,
                         SSH_FORMAT_END);
  ssh_decode_array(buf, sizeof(buf), SSH_FORMAT_MP_INT, NULL,
                         SSH_FORMAT_END);
} 

void test_functions_parse_compound(SshBuffer *buffer, ...)
{
  va_list va;

  va_start(va, buffer);
  if (ssh_decode_array_va(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer), va)
      != 4)
    ssh_fatal("test_functions_parse_compound error");
}

void test_functions(int foo, ...)
{
  va_list va;
  unsigned char *cp;
  
  ssh_buffer_clear(buffer);
  if (ssh_encode_buffer(buffer, SSH_FORMAT_VLINT32, (SshUInt32) 67,
                        SSH_FORMAT_END) != 2)
    ssh_fatal("test_functions: ssh_encode error");
  if (memcmp(ssh_buffer_ptr(buffer), "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode data error");

  ssh_buffer_clear(buffer);
  va_start(va, foo);
  if (ssh_encode_va(buffer, va) != 2)
    ssh_fatal("test_functions: ssh_encode_va error");
  if (memcmp(ssh_buffer_ptr(buffer), "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode_va data error");

  if (ssh_encode_alloc(NULL, SSH_FORMAT_VLINT32, (SshUInt32) 67,
                       SSH_FORMAT_END) != 2)
    ssh_fatal("test_function: ssh_encode_alloc NULL error");
  if (ssh_encode_alloc(&cp, SSH_FORMAT_VLINT32, (SshUInt32) 67,
                       SSH_FORMAT_END) != 2)
    ssh_fatal("test_functions: ssh_encode_alloc error");
  if (memcmp(cp, "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode_alloc data error");
  ssh_xfree(cp);
  cp = NULL;

  if (ssh_encode_alloc_va(NULL, va) != 2)
    ssh_fatal("test_function: ssh_encode_alloc_va NULL error");
  if (ssh_encode_alloc_va(&cp, va) != 2)
    ssh_fatal("test_functions: ssh_encode_alloc_va error");
  if (memcmp(cp, "\100\103", 2) != 0)
    ssh_fatal("test_functions: ssh_encode_alloc_va data error");
  ssh_xfree(cp);

  /* Compound test. */
  ssh_buffer_clear(buffer);
  if (ssh_encode_buffer(buffer,
                        SSH_FORMAT_VLINT32_STR, "A", 1,
                        SSH_FORMAT_BOOLEAN, FALSE,
                        SSH_FORMAT_VLINT32, (SshUInt32) 7,
                        SSH_FORMAT_END) != 4)
    ssh_fatal("test_functions: compound error");
  if (memcmp(ssh_buffer_ptr(buffer), "\1A\0\7", 4) != 0)
    ssh_fatal("test_functions: compound data error");

  {
    Boolean bool;
    SshUInt32 l = 0;
    test_functions_parse_compound(buffer,
                                  SSH_FORMAT_VLINT32_STR, NULL, NULL,
                                  SSH_FORMAT_BOOLEAN, &bool,
                                  SSH_FORMAT_VLINT32, &l,
                                  SSH_FORMAT_END);
    if (bool != FALSE || l != 7)
      ssh_fatal("test_functions: compound parse error");
  }
}

int main()
{
  int pass;

  for (pass = 0; pass < 1000; pass++)
    {
      buffer = ssh_buffer_allocate();
      test_encode();
      test_empty_decode();
      test_random_decode();
      test_functions(0, SSH_FORMAT_VLINT32, (SshUInt32) 67, SSH_FORMAT_END);
      ssh_buffer_free(buffer);
    }

  return 0;
}

/* XXX add SSH_FORMAT_EXTENDED tests. */
