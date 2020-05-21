/*

t-buffer.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 20:38:23 1996 ylo
Last modified: 04:10 May 24 1998 kivinen

*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshbufaux.h"

int main()
{
  int pass, subpass, i;
  unsigned char data[1024];
  SshBuffer b, *bufferp;
  char *s, *s2;
  unsigned char *cp;
  unsigned int len, origlen;
  size_t len2;
  long value;
  SshInt mp1, mp2;

  /* test strings for some cases of ssh2 strings */

  const unsigned char *ssh2test_a[5] = 
  {
    (const unsigned char *) "0",
    (const unsigned char *) "9A378F9B2E332A7",
    (const unsigned char *) "80",
    (const unsigned char *) "-1234",
    (const unsigned char *) "-DEADBEEF"
  };
  const unsigned char ssh2test_b[5][16] =
  { 
    { 0x00, 0x00, 0x00, 0x00}, 
    { 0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 },
    { 0x00, 0x00, 0x00, 0x02, 0x00, 0x80},
    { 0x00, 0x00, 0x00, 0x02, 0xed, 0xcc},
    { 0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11}
    
  };
  const size_t ssh2test_l[5] = 
  { 4, 12, 6, 6, 9 };

  for (pass = 0; pass < 20; pass++)
    {
      ssh_buffer_init(&b);

      for (subpass = 0; subpass < 10; subpass++)
        {
          ssh_buffer_clear(&b);
          s = "this is test data.";
          len = strlen(s) + 1;
          memcpy(data, s, len);
          for (i = 0; i < 2000; i++)
            ssh_buffer_append(&b, data, len);
          origlen = ssh_buffer_len(&b);
          for (i = 0; i < 1000; i++)
            {
              if (memcmp(ssh_buffer_ptr(&b), s, len) != 0)
                {
                  printf("ssh_buffer_ptr fails\n");
                  exit(1);
                }
              memset(ssh_buffer_ptr(&b), 'B', len);
              ssh_buffer_consume(&b, len);
            }
          if (ssh_buffer_len(&b) * 2 != origlen)
            {
              printf("ssh_buffer_len * 2 test fails\n");
              exit(1);
            }
          for (i = 0; i < len; i++)
            {
              if (ssh_buffer_len(&b) != origlen / 2 - i ||
                  memcmp(ssh_buffer_ptr(&b), s, len) != 0)
                {
                  printf("ssh_buffer_consume_end test fails\n");
                  exit(1);
                }
              ssh_buffer_consume_end(&b, 1);
            }
          memset(data, 'A', sizeof(data));
          ssh_buffer_get(&b, data, sizeof(data));
          for (cp = data; cp + len < data + sizeof(data); cp += len)
            if (memcmp(cp, s, len) != 0)
              {
                printf("buffer_get test fails\n");
                exit(1);
              }
          ssh_buffer_clear(&b);
          if (ssh_buffer_len(&b) != 0)
            {
              printf("ssh_buffer_clear test fails\n");
              exit(1);
            }
        }
      ssh_buffer_uninit(&b);
    }




  for (pass = 0; pass < 100; pass++)
    {
      ssh_mp_init_set_str(&mp1, "33234982384932743234328943274893274328443543548584543854358454352304832848230472389472398473284973249832849032849032849302483284723894723198473249321498234732981473298473289473248329987987432473984739587464658256438947324732498632565562389432984", 10);
      ssh_mp_init(&mp2);
      
      ssh_buffer_init(&b);
      for (i = 0; i < 5; i++)
        buffer_put_mp_int(&b, &mp1);
      
      for (i = 0; i < 1000; i++)
        {
          buffer_put_vlint32(&b, i * 1234567L);
          buffer_put_char(&b, i);
          buffer_put_uint32_string(&b, s, len);
        }

      for (i = 0; i < 5; i++)
        {
          buffer_get_mp_int(&b, &mp2);
          if (ssh_mp_cmp(&mp1, &mp2) != 0)
            {
              printf("mp1 = ");
              ssh_mp_out_str(NULL, 16, &mp1);
              printf("\nmp2 = ");
              ssh_mp_out_str(NULL, 16, &mp2);
              printf("\n");
              printf("buffer_get_mp_int failed\n");
              exit(1);
            }
        }
      for (i = 0; i < 1000; i++)
        {
          value = buffer_get_vlint32(&b);
          if (value != i * 1234567L)
            {
              printf("buffer_get_vlint32 failed: i=%d got %ld exp %ld\n",
                     i, value, i * 1234567L);
              exit(1);
            }
          if (buffer_get_char(&b) != i % 256)
            {
              printf("buffer_get_char failed\n");
              exit(1);
            }
          s2 = (char *)buffer_get_uint32_string(&b, &len2);
          if (strcmp(s, s2) != 0 || len2 != len)
            {
              printf("buffer_get_uint32_string failed\n");
              exit(1);
            }
          ssh_xfree(s2);
        }
      if (ssh_buffer_len(&b) != 0)
        {
          printf("buffer not empty at end\n");
          exit(1);
        }
      ssh_buffer_uninit(&b);
      ssh_mp_clear(&mp1);
      ssh_mp_clear(&mp2);
      
      bufferp = ssh_buffer_allocate();
      ssh_buffer_free(bufferp);
    }

  /* primitive tests for ssh-style mp_ints */

  for (i = 0; i < 5; i++)
    {
      ssh_mp_init_set_str(&mp1, (const char *) ssh2test_a[i], 16);
      printf("Input: ");
      ssh_mp_out_str(NULL, 16, &mp1);
      printf("\n");
      ssh_mp_init(&mp2);
      ssh_buffer_init(&b);
      buffer_put_mp_int_ssh2style(&b, &mp1);

      if (b.end - b.offset != ssh2test_l[i])
        ssh_fatal("ssh_put_mp_int_ssh2style failed (%d, len)", i);
      if (memcmp(b.buf+b.offset, ssh2test_b[i], ssh2test_l[i]) != 0)
        ssh_fatal("ssh_put_mp_int_ssh2style failed (%d, match)", i);

      buffer_get_mp_int_ssh2style(&b, &mp2);
      if (ssh_mp_cmp(&mp1, &mp2) != 0)
        ssh_fatal("ssh_get_mp_int_ssh2style failed (%d)", i);

      ssh_mp_clear(&mp1);
      ssh_mp_clear(&mp2);
      ssh_buffer_uninit(&b);
    }


  return 0;
}
