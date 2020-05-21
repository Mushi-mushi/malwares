/*

  gentest.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Nov  1 05:37:55 1996 [mkojo]

  Testing those gen- prefixed files.

  */

/*
 * $Id: t-gentest.c,v 1.26 1999/04/28 00:59:45 kivinen Exp $
 * $Log: t-gentest.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "namelist.h"
#include "sshcrypt.h"
#include "timeit.h"
#include "readfile.h"

#include "testsrcpath.h"

#ifndef PKCS_CNT
#define PKCS_CNT 10
#endif

/******************** Misc. routines. ************************/

void hex_dump(unsigned char *cp, size_t len)
{
  int i;
  for (i = 0; i < len; i++)
    {
      printf("%02x", cp[i]);
    }
}

/********************** Random number tests. **********************/

/* Bit frequency tests. */

unsigned int rnd_bytes[256];
unsigned int rnd_freq[8][8];
unsigned int rnd_bits[8];

void rnd_set_freq(int i)
{
  rnd_bits[i]++;
  if (rnd_freq[i][0])
    {
      if (rnd_freq[i][0] < 7)
        rnd_freq[i][rnd_freq[i][0]]++;
      else
        rnd_freq[i][7]++;
      rnd_freq[i][0] = 0;
    }
}

void rnd_add_freq()
{
  int i;

  for (i = 0; i < 8; i++)
    rnd_freq[i][0]++;
}

void rnd_test_bits(SshRandomState state)
{
  int i, hi, lo, average, j, byte, error = 0;
  double av;
  
  printf("Running random number bit tests...\n");

  for (i = 0; i < 8; i++)
    {
      rnd_bits[i] = 0;
      for (j = 0; j < 8; j++)
        rnd_freq[i][j] = 0;
    }
  for (j = 0; j < 256; j++)
    rnd_bytes[j] = 0;

  for (i = 0; i < 1000000; i++)
    {
      if ((i & 0xffff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      
      byte = ssh_random_get_byte(state) & 0xff;

      rnd_bytes[byte]++;

      if (byte & 128)
        rnd_set_freq(7);
      if (byte & 64)
        rnd_set_freq(6);
      if (byte & 32)
        rnd_set_freq(5);
      if (byte & 16)
        rnd_set_freq(4);
      if (byte & 8)
        rnd_set_freq(3);
      if (byte & 4)
        rnd_set_freq(2);
      if (byte & 2)
        rnd_set_freq(1);
      if (byte & 1)
        rnd_set_freq(0);

      rnd_add_freq();
    }

  printf("\nRandom number generation validation suggests: \n");

  for (j = 0, hi = 0, lo = i, average = 0; j < 256; j++)
    {
      if (rnd_bytes[j] < lo)
        lo = rnd_bytes[j];
      if (rnd_bytes[j] > hi)
        hi = rnd_bytes[j];
    }

  if (hi > 5000 || lo < 3000)
    {
      printf("\nNote: byte distribution is off the set limits.\n");
      error++;
    }
  
  printf("Plain byte distribution: %d tries: %d highest, %d lowest.\n",
         i, hi, lo);

  printf("Single bit distributions, and counts in time.\n");
  
  for (j = 0; j < 8; j++)
    {
      av = ((double)rnd_bits[j]) / (double)i;

      printf("bit %d av. %f  %5d %5d %5d %5d %5d %5d . %5d\n", j,
             av,
             rnd_freq[j][1], rnd_freq[j][2], rnd_freq[j][3], rnd_freq[j][4],
             rnd_freq[j][5], rnd_freq[j][6], rnd_freq[j][7]);

      /* Simple checks for too good results. */
      if (av == 0.5 ||
          (rnd_freq[j][1] == 250000 || rnd_freq[j][2] == 125000 ||
          rnd_freq[j][3] == 62500  || rnd_freq[j][4] == 31250 ||
          rnd_freq[j][5] == 15625))
        {
          printf("\n Note: bit distributions are too good. "
                 "Please check these results.\n");
          error++;
        }
              
      /* Checks for too poor results. */

      if (av < 0.45 || av > 0.55)
        {
          printf("\n Note: average bit distribution is off"
                 " the set limits.\n");
          error++;
        }
      
      if ((rnd_freq[j][1] < 220000 || rnd_freq[j][1] > 270000) ||
          (rnd_freq[j][2] < 120000 || rnd_freq[j][2] > 130000) ||
          (rnd_freq[j][3] <  60000 || rnd_freq[j][3] >  65000) ||
          (rnd_freq[j][4] <  29000 || rnd_freq[j][4] >  33000) ||
          (rnd_freq[j][5] <  14000 || rnd_freq[j][5] >  16000) ||
          (rnd_freq[j][6] <   7000 || rnd_freq[j][6] >   8500) ||
          (rnd_freq[j][7] <   7000 || rnd_freq[j][7] >   8500))
        {
          printf("\n Note: bit distributions in time are "
                 "off the set limits.\n");
          error++;
        }
    }

  printf("\n");


  if (error)
    {
      printf("\nATTENTION: Simple byte and bit tests have shown that \n"
             "this random number generation is performing \"badly\".\n"
             "Please run again few times to see if this error will occur\n"
             "again.\n"
             "If this error occurs often please contact SSH.\n");
      ssh_fatal("Warning: possible failure in random number generation.");
    }
  
}

/* Missing sequence tests. */

void rnd_test_missing_bits(SshRandomState state)
{
  unsigned char *bit_table;
  unsigned int i, l, m;
  double average;
  int error = 0;
  
#define SET_BIT(pos) (bit_table[pos / 8] |= (1 << (pos & 0x7)))
#define GET_BIT(pos) (bit_table[pos / 8] & (1 << (pos & 0x7)))

  printf("Following set of tests give the number of missing sequences\n"
         "after n iterations.\n");
  
  /* Sequence of 2 */

  /* Use 8 bit characters. */

#define SIZE 256*256/8
#define LOOPS SIZE * 16
  
  printf("Running test for sequences of 2 (table size %d bytes).\n", SIZE);
  
  bit_table = ssh_xmalloc(SIZE);
  memset(bit_table, 0, SIZE);

  for (i = 0; i < LOOPS; i++)
    {
      if (i > 0 && (i & 0xfff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      l = ssh_random_get_byte(state) * 256 + ssh_random_get_byte(state);
      SET_BIT(l);
    }

  printf("\nChecking missing sequences...\n");

  for (i = 0, m = 0; i < SIZE * 8; i++)
    {
      if (!GET_BIT(i))
        m++;
    }

  average = ((double)m / (SIZE*8));
  if (average < 0.12 || average > 0.14)
    {
      printf("\n NOTE: Possible error detected.\n");
      error++;
    }
  
  printf("After %d runs: \n"
         "%d of %d missing (average %f after %d full iterations).\n",
         LOOPS, m, SIZE * 8, 
         average, LOOPS/(SIZE*8));

  ssh_xfree(bit_table);
#undef SIZE
#undef LOOPS
  
  /* Sequence of 3 */

  /* Use 7 bit characters. */

#define SIZE 128*128*128/8
#define LOOPS SIZE * 16
  
  printf("Running test for sequences of 3 (table size %d bytes).\n", SIZE);
  
  bit_table = ssh_xmalloc(SIZE);
  memset(bit_table, 0, SIZE);

  for (i = 0; i < LOOPS; i++)
    {
      if (i > 0 && (i & 0x1ffff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      l = (ssh_random_get_byte(state) >> 1) * (128*128) +
        (ssh_random_get_byte(state) >> 1) * 128 +
        (ssh_random_get_byte(state) >> 1);
      SET_BIT(l);
    }

  printf("\nChecking missing sequences...\n");

  for (i = 0, m = 0; i < SIZE * 8; i++)
    {
      if (!GET_BIT(i))
        m++;
    }

  average = ((double)m / (SIZE*8));
  if (average < 0.12 || average > 0.14)
    {
      printf("\n NOTE: Possible error detected.\n");
      error++;
    }
  
  printf("After %d runs: \n"
         "%d of %d missing (average %f after %d full iterations).\n",
         LOOPS, m, SIZE * 8, 
         average, LOOPS/(SIZE*8));

  ssh_xfree(bit_table);
#undef SIZE
#undef LOOPS

  /* Sequence of 4 */

  /* Use 5 bit characters. */

#define SIZE 32*32*32*32/8
#define LOOPS SIZE * 16
  
  printf("Running test for sequences of 4 (table size %d bytes).\n", SIZE);
  
  bit_table = ssh_xmalloc(SIZE);
  memset(bit_table, 0, SIZE);

  for (i = 0; i < LOOPS; i++)
    {
      if (i > 0 && (i & 0xffff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      l = (ssh_random_get_byte(state) >> 3) * (32*32*32) +
        (ssh_random_get_byte(state) >> 3) * (32*32) +
        (ssh_random_get_byte(state) >> 3) * 32 +
        (ssh_random_get_byte(state) >> 3);
      SET_BIT(l);
    }

  printf("\nChecking missing sequences...\n");

  for (i = 0, m = 0; i < SIZE * 8; i++)
    {
      if (!GET_BIT(i))
        m++;
    }

  average = ((double)m / (SIZE*8));
  if (average < 0.12 || average > 0.14)
    {
      printf("\n NOTE: Possible error detected.\n");
      error++;
    }
  
  printf("After %d runs: \n"
         "%d of %d missing (average %f after %d full iterations).\n",
         LOOPS, m, SIZE * 8, 
         average, LOOPS/(SIZE*8));
  
  ssh_xfree(bit_table);
#undef SIZE
#undef LOOPS

  /* Sequence of 5 */

  /* Use 4 bit characters. */

#define SIZE 16*16*16*16*16/8
#define LOOPS SIZE * 16
  
  printf("Running test for sequences of 5 (table size %d bytes).\n", SIZE);
  
  bit_table = ssh_xmalloc(SIZE);
  memset(bit_table, 0, SIZE);

  for (i = 0; i < LOOPS; i++)
    {
      if (i > 0 && (i & 0xffff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      l = (ssh_random_get_byte(state) >> 4) * (16*16*16*16) +
        (ssh_random_get_byte(state) >> 4) * (16*16*16) +
        (ssh_random_get_byte(state) >> 4) * (16*16) +
        (ssh_random_get_byte(state) >> 4) * 16 +
        (ssh_random_get_byte(state) >> 4);
      SET_BIT(l);
    }

  printf("\nChecking missing sequences...\n");

  for (i = 0, m = 0; i < SIZE * 8; i++)
    {
      if (!GET_BIT(i))
        m++;
    }

  average = ((double)m / (SIZE*8));
  if (average < 0.12 || average > 0.14)
    {
      printf("\n NOTE: Possible error detected.\n");
      error++;
    }
  
  printf("After %d runs: \n"
         "%d of %d missing (average %f after %d full iterations).\n",
         LOOPS, m, SIZE * 8, 
         average, LOOPS/(SIZE*8));
  
  ssh_xfree(bit_table);
#undef SIZE
#undef LOOPS

  /* Sequence of 5 */

  /* Use 3 bit characters. */

#define SIZE 8*8*8*8*8*8/8
#define LOOPS SIZE * 16
  
  printf("Running test for sequences of 6 (table size %d bytes).\n", SIZE);
  
  bit_table = ssh_xmalloc(SIZE);
  memset(bit_table, 0, SIZE);

  for (i = 0; i < LOOPS; i++)
    {
      if (i > 0 && (i & 0x3fff) == 0)
        {
          printf(".");
          fflush(stdout);
        }
      l = (ssh_random_get_byte(state) >> 5) * (8*8*8*8*8) +
        (ssh_random_get_byte(state) >> 5) * (8*8*8*8) +
        (ssh_random_get_byte(state) >> 5) * (8*8*8) +
        (ssh_random_get_byte(state) >> 5) * (8*8) +
        (ssh_random_get_byte(state) >> 5) * 8 +
        (ssh_random_get_byte(state) >> 5);
      SET_BIT(l);
    }

  printf("\nChecking missing sequences...\n");

  for (i = 0, m = 0; i < SIZE * 8; i++)
    {
      if (!GET_BIT(i))
        m++;
    }

  average = ((double)m / (SIZE*8));
  if (average < 0.12 || average > 0.14)
    {
      printf("\n NOTE: Possible error detected.\n");
      error++;
    }
  
  ssh_xfree(bit_table);
#undef SIZE
#undef LOOPS

  printf("\n");

  if (error > 2)
    {
      printf("\nATTENTION: Random statistics checks failed %d times.\n"
             "It is however possible that there is nothing wrong with it\n"
             "but to be safe run this test again.\n"
             "\nContact SSH if this error appears more than few times.\n",
             error);
      ssh_fatal("Warning: possible failure in random number generation.");
    }
}

void test_random(SshRandomState state, int flag)
{
  /* Run the simple bit testing. */
  printf(" - bit tests.\n");
  rnd_test_bits(state);

  /* Run the missing sequence tests. */
  printf(" - sequence tests.\n");
  rnd_test_missing_bits(state);

  /* Random tests ends. */
}

/****************** Hash tests. ***********************/


void hash_random_tests(SshRandomState state)
{
  char *namelist = ssh_hash_get_supported();
  const char *tmp_namelist = namelist;
  char *hash_name = NULL;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH],
    *buf2;
  SshHash hash;
  TimeIt tmit;
  int i, len;
  
  while ((hash_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
        ssh_fatal("error: hash allocate %s failed.", hash_name);

      /* Put here some tests. */

      len = 1000;
    retry:
      buf2 = ssh_xmalloc(len);
      for (i = 0; i < len; i++)
        buf2[i] = i & 0xff;

      start_timing(&tmit);
      
      for (i = 0; i < 1024; i++)
        ssh_hash_update(hash, buf2, len);

      check_timing(&tmit);
      
      ssh_hash_final(hash, buf);

      ssh_xfree(buf2);
      
      if (tmit.real_secs <= 1.0 && len < 10000000)
        {
          len *= 2;
          printf("  - %s was too fast, retrying...\n", hash_name);
          goto retry;
        }

      if (tmit.real_secs >= 1.0)
        printf("%s timed to update at rate %f KBytes/sec.\n",
               hash_name, ((double)len) / (tmit.real_secs));
      else
        printf("  - timing could not be performed for %s.\n", hash_name);
      
      
      /* Put here some tests. */

      ssh_xfree(hash_name);      
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);

      ssh_hash_free(hash);
    }
  
  ssh_xfree(namelist);
}

/* Read the file. */
void hash_static_tests()
{
  char hash_name[256];
  unsigned char *str;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH];
  SshHash hash = NULL;
  size_t len;
  int i;
  RFStatus status;
#define HASH_IGNORE 0
#define HASH_INPUT 1
#define HASH_OUTPUT 2
  unsigned int state = HASH_IGNORE;
  
  status = ssh_t_read_init(TEST_SRC_PATH "/hash.tests");
  if (status != RF_READ)
    ssh_fatal("error: hash.tests file not available or corrupted.");

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          /* Delete the old hash context. */
          if (hash)
            ssh_hash_free(hash);
          if (len > 255)
            ssh_fatal("error: hash name too long.");
          memcpy(hash_name, str, len);
          hash_name[len] = '\0';

          if (ssh_hash_supported(hash_name))
            {
              if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
                ssh_fatal("error: hash allocate %s failed.", hash_name);
              state = HASH_INPUT;
            }
          else
            {
              ssh_debug("hash %s not supported", hash_name);
              state = HASH_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case HASH_INPUT:          
              ssh_hash_reset(hash);
              ssh_hash_update(hash, str, len);
              state = HASH_OUTPUT;
              break;
            case HASH_OUTPUT:
              ssh_hash_final(hash, buf);
              if (len != ssh_hash_digest_length(hash))
                ssh_fatal("error: file digest length incorrect.");
              
              if (memcmp(str, buf, ssh_hash_digest_length(hash)) != 0)
                {
                  printf("Wrong digest: ");
                  for (i = 0; i < ssh_hash_digest_length(hash); i++)
                    {
                      printf("%02x", buf[i]);
                    }
                  printf("\nShould be digest: ");
                  for (i = 0; i < ssh_hash_digest_length(hash); i++)
                    {
                      printf("%02x", str[i]);
                    }
                  printf("\n");
                  ssh_fatal("error: %s failed.", hash_name);
                }
              state = HASH_INPUT;
              break;
            case HASH_IGNORE:
              break;
            default:
              ssh_fatal("error: unknown hash flag (%d).", state);
              break;
            }
          
          break;
        case RF_EMPTY:
          break;
        default:
          ssh_fatal("error: file error or corrupted (%d).", status);
          break;
        }
    }

  ssh_t_close();
  
  if (hash)
    ssh_hash_free(hash);
}

void hash_static_tests_do(SshRandomState state)
{
  char *namelist = ssh_hash_get_supported();
  const char *tmp_namelist = namelist;
  char *hash_name = NULL;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH],
    *buf2;
  SshHash hash;
  int i, j, len;
  RFStatus status;
  
  status = ssh_t_write_init("hash.tests.created");
  if (status != RF_WRITE)
    ssh_fatal("error: file hash.tests.created could not be created.");
  
  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  buf2 = (unsigned char *) TEST_SRC_PATH "/hash.tests";
  ssh_t_write_token(RF_COMMENT, buf2, strlen((char *) buf2));
  
  while ((hash_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
        ssh_fatal("error: hash allocate %s failed.", hash_name);

      /* Put here some tests. */

      ssh_t_write_token(RF_LINEFEED, NULL, 0);
      ssh_t_write_token(RF_LABEL, (unsigned char *) hash_name,
                        strlen(hash_name));
      ssh_t_write_token(RF_LINEFEED, NULL, 0);

      for (i = 0; i < 64; i++)
        {
          buf2 = (unsigned char *) "first input then digest";
          ssh_t_write_token(RF_COMMENT, buf2, strlen((char *) buf2));
          
          len = i + 10;
          buf2 = ssh_xmalloc(len);
          for (j = 0; j < len; j++)
            buf2[j] = ssh_random_get_byte(state);

          ssh_t_write_token(RF_HEX, buf2, len);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          ssh_hash_reset(hash);
          ssh_hash_update(hash, buf2, len);
          ssh_hash_final(hash, buf);

          ssh_t_write_token(RF_HEX, buf, ssh_hash_digest_length(hash));
          ssh_t_write_token(RF_LINEFEED, NULL, 0);
          
          ssh_xfree(buf2);
        }

      /* Put here some tests. */

      ssh_xfree(hash_name);      
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);

      ssh_hash_free(hash);
    }

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  buf2 = (unsigned char *) TEST_SRC_PATH "/hash.tests";
  ssh_t_write_token(RF_COMMENT, buf2, strlen((char *) buf2));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  ssh_t_close();
  
  ssh_xfree(namelist);
}

void test_hash(SshRandomState state, int flag)
{
  if (flag & 0x2)
    {
      printf(" - random tests (with timing).\n");
      hash_random_tests(state);
    }
  if (flag & 0x8)
    {
      printf(" - generating static test cases.\n");
      hash_static_tests_do(state);
    }
  if (flag & 0x4)
    {
      printf(" - running static tests.\n");
      hash_static_tests();
    }
}


/*********************** MAC tests. *****************************/


void mac_random_tests(SshRandomState state)
{
  char *namelist = ssh_mac_get_supported();
  const char *tmp_namelist = namelist;
  char *mac_name = NULL;
  unsigned char *key;
  SshUInt32 keylen;
  unsigned char *buf;
  unsigned char *buf2;
  SshMac mac;
  TimeIt tmit;
  int i, len;
  
  while ((mac_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      keylen = (SshUInt32)ssh_random_get_byte(state);
      key = ssh_xmalloc(keylen);
      
      for (i = 0; i < keylen; i++)
        key[i] = ssh_random_get_byte(state);

      if (ssh_mac_allocate(mac_name, key, keylen, &mac) != SSH_CRYPTO_OK)
        ssh_fatal("error: mac allocate %s failed.", mac_name);

      ssh_xfree(key);
      
      buf = ssh_xmalloc(ssh_mac_length(mac));

      len = 1000;
    retry:
      buf2 = ssh_xmalloc(len);

      for (i = 0; i < len; i++)
        buf2[i] = (i & 0xff);
      
      /* Put here some tests. */
      
      ssh_mac_start(mac);

      start_timing(&tmit);
      
      for (i = 0; i < 1024; i++)
        {
          ssh_mac_update(mac, buf2, len);
        }

      check_timing(&tmit);

      ssh_xfree(buf2);
      
      if (tmit.real_secs <= 1.0 && len < 10000000)
        {
          len *= 2;
          printf("  - %s was too fast, retrying...\n", mac_name);
          goto retry;
        }

      if (tmit.real_secs >= 1.0)
        printf("%s timed to update at rate %f KBytes/sec.\n",
               mac_name, ((double)len) / (tmit.real_secs));
      else
        printf("  - timing could not be performed for %s.\n", mac_name);
      
      
      ssh_mac_final(mac, buf);

      /* Put here some tests. */
      
      ssh_xfree(buf);
      ssh_xfree(mac_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);

      ssh_mac_free(mac);
    }
  ssh_xfree(namelist);
}

void mac_static_tests()
{
  char mac_name[256];
  unsigned char *buf = NULL;
  unsigned char *str;
  size_t len;
  int i;
  SshMac mac = NULL;
  RFStatus status;
#define MAC_IGNORE 0
#define MAC_READ_KEY 1
#define MAC_OUTPUT   2
#define MAC_INPUT    3
  unsigned int state = MAC_IGNORE;
  
  status = ssh_t_read_init(TEST_SRC_PATH "/mac.tests");
  if (status != RF_READ)
    ssh_fatal("error: file mac.tests not available.");

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          if (mac != NULL)
            {
              ssh_mac_free(mac);
              ssh_xfree(buf);
            }
          
          if (len > 256)
            ssh_fatal("error: mac name too long.");
          memcpy(mac_name, str, len);
          mac_name[len] = '\0';

          if (ssh_mac_supported(mac_name))
            state = MAC_READ_KEY;
          else
            {
              ssh_debug("mac %s not supported", mac_name);
              state = MAC_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case MAC_READ_KEY:
              if (ssh_mac_allocate(mac_name, str, len, &mac) != SSH_CRYPTO_OK)
                ssh_fatal("error: mac allocate %s failed.", mac_name);

              buf = ssh_xmalloc(ssh_mac_length(mac));

              state = MAC_INPUT;
              break;
            case MAC_INPUT:
              ssh_mac_start(mac);
              ssh_mac_update(mac, str, len);
              state = MAC_OUTPUT;
              break;
            case MAC_OUTPUT:
              ssh_mac_final(mac, buf);

              if (len < ssh_mac_length(mac))
                ssh_fatal("error: file mac output too short.");

              if (memcmp(str, buf, ssh_mac_length(mac)) != 0)
                {
                  printf("Wrong digest: ");
                  for (i = 0; i < ssh_mac_length(mac); i++)
                    {
                      printf("%02x", buf[i]);
                    }
                  printf("\nShould be digest: ");
                  for (i = 0; i < ssh_mac_length(mac); i++)
                    {
                      printf("%02x", str[i]);
                    }
                  printf("\n");
                  ssh_fatal("error: mac %s failed.", mac_name);
                }

              state = MAC_INPUT;
              break;
            case MAC_IGNORE:
              break;
            default:
              ssh_fatal("error: unknown state (%d).", state);
              break;
            }
        case RF_EMPTY:
          break;
        default:
          ssh_fatal("error: file corrupted (%d).", status);
          break;
        }
    }
  
  ssh_t_close();
  ssh_mac_free(mac);
  ssh_xfree(buf);
}

void mac_static_tests_do(SshRandomState state)
{
  char *namelist = ssh_mac_get_supported();
  const char *tmp_namelist = namelist;
  char *mac_name = NULL;
  unsigned char *key;
  size_t keylen;
  unsigned char *buf;
  unsigned char *buf2;
  SshMac mac;
  int i, j, k, len;
  RFStatus status;

  status = ssh_t_write_init("mac.tests.created");
  if (status != RF_WRITE)
    ssh_fatal("error: could not open mac.tests.created for writing.");

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  buf2 = (unsigned char *) TEST_SRC_PATH "/mac.tests";
  ssh_t_write_token(RF_COMMENT, buf2, strlen((char *) buf2));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  
  while ((mac_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      ssh_t_write_token(RF_COMMENT, (unsigned char *) mac_name,
                        strlen(mac_name));
      for (k = 0; k < 16; k++)
        {
          keylen = (ssh_random_get_byte(state) + 1) & 31;
          key = ssh_xmalloc(keylen);
          
          for (i = 0; i < keylen; i++)
            key[i] = ssh_random_get_byte(state);
          
          if (ssh_mac_allocate(mac_name, key, keylen, &mac) != SSH_CRYPTO_OK)
            ssh_fatal("error: mac allocate %s failed.", mac_name);
          
          ssh_t_write_token(RF_LINEFEED, NULL, 0);
          ssh_t_write_token(RF_LABEL, (unsigned char *) mac_name,
                            strlen(mac_name));
          
          ssh_t_write_token(RF_HEX, key, keylen);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);
          
          ssh_xfree(key);

          for (j = 0; j < 8; j++)
            {
      
              buf = ssh_xmalloc(ssh_mac_length(mac));
              
              len = j*2 + 10;
              buf2 = ssh_xmalloc(len);
              
              for (i = 0; i < len; i++)
                buf2[i] = ssh_random_get_byte(state);

              ssh_t_write_token(RF_HEX, buf2, len);
              
              /* Put here some tests. */
              
              ssh_mac_start(mac);
              
              ssh_mac_update(mac, buf2, len);
              ssh_xfree(buf2);
              
              ssh_mac_final(mac, buf);

              ssh_t_write_token(RF_HEX, buf, ssh_mac_length(mac));

              ssh_t_write_token(RF_LINEFEED, NULL, 0);
              
              /* Put here some tests. */
              
              ssh_xfree(buf);
            }
          ssh_mac_free(mac);
        }
      ssh_xfree(mac_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
    }
  ssh_xfree(namelist);

  ssh_t_close();
}

void test_mac(SshRandomState state, int flag)
{
  if (flag & 0x2)
    {
      printf(" - random tests (with timing).\n");
      mac_random_tests(state);
    }
  if (flag & 0x8)
    {
      printf(" - creating static test cases.\n");
      mac_static_tests_do(state);
    }
  if (flag & 0x4)
    {
      printf(" - running static tests.\n");
      mac_static_tests(state);
    }
}


/********************** Cipher tests ******************************/


/* XXX Triple DES verification bytes. */

#if 0

void test_3des_cipher_verify(void)
{
  /* Key */
  static unsigned char key[24] = 
  { 0x7a, 0xc2, 0x98, 0xe7, 0x61, 0x05, 0x1e, 0x0d, 
    0xbe, 0x13, 0xf9, 0xe0, 0x66, 0xcb, 0x46, 0x6c, 
    0xbd, 0xf3, 0x35, 0xb7, 0xe9, 0xa6, 0x54, 0x0b, };

  /* 8 bytes for plaintext and 8 bytes for ciphertext about 100 both. */
  static unsigned char s_data[1600] = 
  {0x20, 0xd1, 0x00, 0xef, 0x9e, 0xa3, 0x48, 0x59, 
   0x37, 0x9e, 0x6c, 0x04, 0x09, 0x78, 0x76, 0xcb, 
   0xc5, 0x7f, 0x69, 0xef, 0xda, 0xd6, 0x0e, 0x43, 
   0x77, 0x5c, 0xdb, 0xca, 0x25, 0x04, 0x31, 0x4a, 
   0x2e, 0xf2, 0x2d, 0x92, 0x78, 0x2d, 0xa4, 0x85, 
   0x68, 0xf3, 0x2f, 0xda, 0x44, 0x4d, 0x4c, 0x66, 
   0x44, 0xbe, 0x60, 0x37, 0x63, 0xae, 0x2f, 0xa1, 
   0x4f, 0x10, 0x5e, 0x68, 0xed, 0xc0, 0x60, 0x8e, 
   0xf3, 0x2c, 0xe1, 0x31, 0x74, 0xd8, 0x79, 0x70, 
   0xb4, 0x9a, 0xee, 0x98, 0x99, 0x8b, 0x73, 0xe0, 
   0xd0, 0xc3, 0xd0, 0x81, 0xc4, 0x69, 0x93, 0xdb, 
   0x7c, 0xb4, 0x56, 0x72, 0xcf, 0x4f, 0x7f, 0x01, 
   0xec, 0x4a, 0x7a, 0xee, 0xac, 0xbe, 0x24, 0x51, 
   0xa4, 0xad, 0x0e, 0x15, 0x08, 0xf8, 0x8b, 0x8a, 
   0xeb, 0xdf, 0x87, 0x82, 0x22, 0x33, 0x2f, 0x7b, 
   0x2d, 0x19, 0x62, 0x19, 0xf5, 0x38, 0x03, 0x37, 
   0x33, 0x41, 0xf8, 0x81, 0xec, 0x73, 0x43, 0x50, 
   0x22, 0x29, 0x3d, 0x5c, 0x60, 0x2a, 0x3e, 0x0b, 
   0x4d, 0xde, 0x47, 0x41, 0xb9, 0x0e, 0xf0, 0x68, 
   0xc1, 0x6a, 0xa2, 0xf5, 0x50, 0xa0, 0xf0, 0x55, 
   0x3e, 0x5d, 0xf6, 0x11, 0x8b, 0x3b, 0x4f, 0x0d, 
   0xf1, 0xba, 0xa7, 0x50, 0x5b, 0xaa, 0x12, 0x66, 
   0xd0, 0x12, 0x36, 0x54, 0x0a, 0x64, 0x15, 0x90, 
   0xca, 0xab, 0x9e, 0x9c, 0x60, 0x6e, 0x35, 0xa9, 
   0xb5, 0x9e, 0x16, 0x2b, 0x85, 0xc4, 0x71, 0xd9, 
   0x2a, 0xaf, 0x82, 0x78, 0x73, 0x05, 0x54, 0x89, 
   0x2e, 0x0b, 0x28, 0x6f, 0xa8, 0xef, 0xe9, 0x04, 
   0x83, 0xe1, 0xb5, 0xee, 0x0f, 0x5e, 0x6d, 0x84, 
   0x56, 0x2d, 0xa6, 0xbf, 0xb0, 0x97, 0xd6, 0x04, 
   0x44, 0xf5, 0x3e, 0x01, 0x9f, 0x6c, 0xee, 0x40, 
   0xc7, 0x3b, 0xce, 0xbd, 0x7f, 0x47, 0xb7, 0xdd, 
   0xfb, 0xbb, 0x5b, 0x48, 0x40, 0x97, 0xfc, 0xac, 
   0x07, 0x36, 0x6e, 0x06, 0xaa, 0xae, 0xf4, 0x50, 
   0x95, 0x5d, 0xd1, 0x25, 0x3a, 0x7e, 0x89, 0xde, 
   0x05, 0x72, 0xeb, 0x7a, 0x3d, 0x6e, 0xa5, 0x53, 
   0xbb, 0x08, 0xd7, 0xa0, 0x48, 0x7b, 0xac, 0x4f, 
   0xa9, 0xd7, 0x05, 0x83, 0x00, 0x53, 0x5c, 0x26, 
   0x44, 0x12, 0x6f, 0xe4, 0x3b, 0xed, 0x70, 0x02, 
   0x45, 0xd3, 0x80, 0x99, 0x85, 0x83, 0xd9, 0x3a, 
   0x33, 0x08, 0x4e, 0xaa, 0x9d, 0xeb, 0x13, 0xd1, 
   0xd6, 0x22, 0x82, 0x63, 0xae, 0xe5, 0x25, 0x44, 
   0xcc, 0x75, 0xa0, 0x48, 0xc7, 0x27, 0x96, 0x6b, 
   0xd6, 0x0c, 0x78, 0x6e, 0x99, 0x46, 0x65, 0x2a, 
   0x62, 0x15, 0x49, 0x25, 0x75, 0x6b, 0x4d, 0xc9, 
   0x0c, 0x6a, 0x53, 0x1e, 0xc3, 0x42, 0x14, 0xb3, 
   0xeb, 0xb6, 0xe9, 0x5f, 0x31, 0x6f, 0x8c, 0xc0, 
   0x98, 0xc2, 0xe9, 0xe8, 0xf4, 0xb0, 0x33, 0xe8, 
   0x34, 0x00, 0x41, 0xc2, 0x1b, 0xfc, 0x10, 0x93, 
   0x79, 0xc3, 0x5f, 0x3f, 0x77, 0x65, 0x3a, 0xda, 
   0x17, 0xf3, 0x62, 0x9f, 0x04, 0xd6, 0x47, 0xea, 
   0xcd, 0x73, 0xf4, 0xca, 0xa8, 0x58, 0x28, 0x57, 
   0xde, 0xac, 0xf8, 0x94, 0x36, 0x3a, 0xd5, 0x92, 
   0xb6, 0x67, 0x17, 0xea, 0xe9, 0x0b, 0xa2, 0xdc, 
   0xd4, 0x1d, 0xa8, 0x5a, 0x2d, 0x92, 0x9e, 0xc6, 
   0xfe, 0x48, 0x39, 0x36, 0xd7, 0x16, 0x31, 0x20, 
   0xff, 0x8f, 0xd7, 0x6a, 0xd1, 0xb4, 0x58, 0xaf, 
   0x76, 0xb6, 0xae, 0x01, 0x0f, 0x3e, 0x18, 0xb5, 
   0xbe, 0xcd, 0xdf, 0x94, 0x26, 0xb4, 0x72, 0xd8, 
   0x8e, 0x71, 0x41, 0x88, 0xce, 0xd2, 0xd2, 0xe1, 
   0x19, 0xec, 0x84, 0xf6, 0xb7, 0x80, 0x01, 0xcd, 
   0x6f, 0x56, 0xef, 0xdf, 0x97, 0x1e, 0xb2, 0x3c, 
   0x28, 0x86, 0xd9, 0x46, 0x42, 0xf3, 0x17, 0x6c, 
   0x03, 0x31, 0x04, 0x7a, 0x7d, 0xa4, 0xbd, 0x10, 
   0xef, 0xeb, 0xb8, 0xc6, 0x6d, 0xa8, 0x7d, 0x9d, 
   0xdc, 0x69, 0x5a, 0xc2, 0x7b, 0xf9, 0x9d, 0x08, 
   0xf1, 0xec, 0xf1, 0xe5, 0x74, 0x62, 0x5a, 0x31, 
   0x52, 0xed, 0x80, 0x1b, 0xe8, 0xae, 0x20, 0x3d, 
   0xbd, 0xcc, 0x2a, 0xf9, 0x3f, 0xca, 0x82, 0xba, 
   0xd5, 0xb2, 0xce, 0xd5, 0xfd, 0xf3, 0xb2, 0x21, 
   0xdc, 0x35, 0x0b, 0xf1, 0xd8, 0x5b, 0x75, 0x94, 
   0xc1, 0x9b, 0x07, 0xc5, 0xe7, 0x83, 0x0a, 0x16, 
   0xcc, 0x49, 0x46, 0x1a, 0x3e, 0xd0, 0x00, 0x01, 
   0x11, 0x98, 0xe0, 0x15, 0x87, 0x4f, 0x37, 0xfe, 
   0xc7, 0xad, 0x60, 0x5a, 0x15, 0x65, 0x02, 0x17, 
   0xda, 0x64, 0x82, 0x8d, 0x19, 0x3e, 0x7a, 0xd9, 
   0x65, 0x50, 0x18, 0x2a, 0x85, 0x7e, 0xe6, 0x8f, 
   0x86, 0x38, 0x3f, 0x69, 0xae, 0x56, 0xf5, 0x5e, 
   0x2f, 0x26, 0xdb, 0x32, 0x39, 0xe2, 0x76, 0x64, 
   0x4f, 0xb3, 0x99, 0xd0, 0xa0, 0x36, 0xc6, 0xfd, 
   0x3f, 0x18, 0x09, 0xc0, 0x11, 0x18, 0xf0, 0x4b, 
   0xb9, 0xf8, 0xa1, 0x15, 0x32, 0x00, 0x80, 0xde, 
   0x1f, 0x63, 0xa3, 0xe2, 0x94, 0x98, 0x54, 0x2f, 
   0xa3, 0xb3, 0xa2, 0xd4, 0xc2, 0x09, 0x12, 0x61, 
   0xb3, 0x75, 0x64, 0xf5, 0x30, 0xd1, 0x2d, 0xed, 
   0x29, 0xf9, 0xba, 0x4f, 0x6c, 0x31, 0x65, 0x63, 
   0x83, 0xc8, 0xb8, 0x03, 0xbd, 0xf3, 0x85, 0xa9, 
   0xdf, 0x38, 0xe3, 0x7b, 0x44, 0xe0, 0x81, 0xab, 
   0x3b, 0x2b, 0x23, 0x70, 0x32, 0xa5, 0xd3, 0x33, 
   0x72, 0xdd, 0xb3, 0xec, 0x7f, 0x9b, 0xcb, 0x96, 
   0xfa, 0xdd, 0x32, 0x59, 0x5c, 0xe4, 0x13, 0x06, 
   0x1a, 0xd2, 0xfc, 0x4f, 0x39, 0x52, 0x9f, 0x2c, 
   0xdc, 0x51, 0xb7, 0xc2, 0x3a, 0x59, 0xc4, 0x77, 
   0x00, 0x79, 0x92, 0xad, 0x02, 0x6f, 0xb2, 0x98, 
   0xfb, 0xa0, 0xa7, 0xff, 0xf2, 0xb7, 0x68, 0x06, 
   0x2a, 0x13, 0x4c, 0x3e, 0xca, 0x5b, 0x34, 0xe4, 
   0x3b, 0x95, 0xc4, 0x96, 0xa9, 0x5b, 0x54, 0xfa, 
   0xf4, 0x6f, 0x82, 0x06, 0xac, 0x57, 0x45, 0xdb, 
   0x96, 0x7a, 0x7c, 0x43, 0xa4, 0x50, 0xd2, 0x6a, 
   0xe2, 0x3e, 0xef, 0xd0, 0x7e, 0x25, 0x40, 0xd1, 
   0x93, 0xdc, 0x89, 0xe5, 0xe9, 0xb4, 0x39, 0x65, 
   0x96, 0xa1, 0xb1, 0x4c, 0x90, 0x5a, 0xf0, 0x7e, 
   0xb5, 0x93, 0x59, 0xee, 0x5d, 0x96, 0x24, 0xf1, 
   0xbe, 0x97, 0x25, 0xe4, 0x6b, 0x84, 0x33, 0x6b, 
   0xfc, 0xf7, 0xe9, 0x6e, 0xfc, 0xb8, 0x10, 0x6f, 
   0xd4, 0x3f, 0x81, 0xc8, 0xd1, 0xc8, 0x0e, 0x4f, 
   0x69, 0xbd, 0xc6, 0x76, 0x82, 0x46, 0x07, 0x39, 
   0x34, 0xc7, 0xf0, 0xbc, 0xa7, 0xec, 0x43, 0xb0, 
   0x3a, 0xa4, 0x27, 0x7c, 0x73, 0x2a, 0x1b, 0x8e, 
   0x6a, 0x14, 0xe9, 0x04, 0x57, 0x1f, 0x87, 0x02, 
   0x75, 0x8c, 0xb3, 0x5d, 0x70, 0x79, 0xa7, 0xde, 
   0x70, 0x0d, 0x76, 0x9f, 0x71, 0xe8, 0x22, 0x58, 
   0xab, 0x98, 0x9a, 0x5a, 0x80, 0xfa, 0xd7, 0xf3, 
   0x7b, 0xce, 0xf7, 0x51, 0x43, 0x0f, 0x00, 0x38, 
   0x18, 0xa8, 0x59, 0x78, 0xc7, 0x7b, 0x5c, 0xa0, 
   0x1e, 0x5e, 0x94, 0x11, 0xf0, 0x65, 0xf0, 0xc6, 
   0x3c, 0x96, 0x0a, 0x75, 0xf2, 0xb1, 0x8a, 0x30, 
   0xdf, 0x7c, 0xf2, 0x09, 0x85, 0x1a, 0xb5, 0x22, 
   0xfd, 0xa4, 0xc3, 0xb3, 0xa7, 0x0c, 0x7a, 0x26, 
   0x0c, 0x89, 0x0c, 0x68, 0xd9, 0xe7, 0x09, 0x23, 
   0xc6, 0xa5, 0x50, 0xd8, 0xa3, 0xd1, 0x41, 0xc4, 
   0x6f, 0xfd, 0x7f, 0x95, 0xed, 0xf9, 0xf4, 0x11, 
   0x7b, 0x28, 0xc8, 0x5c, 0xa1, 0xab, 0x4c, 0x1b, 
   0x93, 0x19, 0x22, 0xc0, 0xcc, 0xae, 0x2c, 0x0c, 
   0xdb, 0x97, 0x8b, 0x33, 0x20, 0x82, 0x82, 0x36, 
   0x35, 0xc9, 0x45, 0xfc, 0x85, 0x63, 0x98, 0x8a, 
   0x45, 0x6d, 0xe9, 0x20, 0xa9, 0x2f, 0x00, 0xcd, 
   0x60, 0xab, 0xfe, 0x98, 0xfc, 0x90, 0x8f, 0x68, 
   0x44, 0xce, 0x87, 0xbe, 0x18, 0x95, 0xf7, 0xcc, 
   0x86, 0xf3, 0x6c, 0x90, 0x0d, 0x06, 0xb2, 0xb7, 
   0x00, 0x2f, 0x5f, 0x4a, 0xc7, 0xcc, 0x5a, 0x2d, 
   0x46, 0xe9, 0x0f, 0xdb, 0xa1, 0xbf, 0x41, 0xc6, 
   0xd6, 0x1b, 0xb8, 0x67, 0x42, 0xef, 0x52, 0x28, 
   0x31, 0x73, 0xc5, 0x39, 0x8e, 0x61, 0xc5, 0x06, 
   0xfb, 0x68, 0x7b, 0xb8, 0x8e, 0x99, 0x98, 0xed, 
   0xfe, 0x66, 0x6b, 0xce, 0x67, 0x9e, 0xef, 0xe8, 
   0x6f, 0xe5, 0x2a, 0x77, 0x52, 0x61, 0x7d, 0x14, 
   0x17, 0x6c, 0xe8, 0x42, 0xde, 0xd3, 0xfd, 0xe3, 
   0x60, 0xcf, 0x20, 0xdc, 0xcf, 0x52, 0x81, 0x39, 
   0x5b, 0xbf, 0xd1, 0x22, 0x0b, 0xe4, 0xbc, 0xe0, 
   0xa5, 0xfa, 0x03, 0x6b, 0xce, 0x34, 0x2c, 0x0b, 
   0xec, 0xd0, 0xab, 0xad, 0xf4, 0x15, 0x44, 0x56, 
   0xb6, 0xd3, 0x16, 0x01, 0x77, 0x57, 0x4c, 0x8b, 
   0x86, 0x41, 0xdc, 0x90, 0xc6, 0x71, 0xb1, 0x4d, 
   0xd1, 0xc1, 0x5f, 0x71, 0x06, 0x14, 0x57, 0xc6, 
   0x9b, 0x85, 0xa2, 0x02, 0xef, 0x95, 0xa8, 0xfa, 
   0x6a, 0xdc, 0x6f, 0xab, 0xe9, 0x6e, 0x18, 0x77, 
   0x52, 0x4e, 0x10, 0xd7, 0xe4, 0x0b, 0x1b, 0x56, 
   0x58, 0xc4, 0x7e, 0x1b, 0x12, 0x5f, 0x2f, 0xd9, 
   0x5b, 0x14, 0x91, 0xf8, 0xeb, 0x2d, 0x80, 0xc9, 
   0xf2, 0xaa, 0x04, 0x7b, 0x4b, 0x5c, 0x12, 0xbc, 
   0x9a, 0xfa, 0xfd, 0x4e, 0x9f, 0xaa, 0x8b, 0x29, 
   0xa2, 0xdc, 0x89, 0xef, 0x78, 0x8d, 0x31, 0x79, 
   0x7c, 0x15, 0x61, 0x80, 0x74, 0x60, 0x72, 0xfb, 
   0x93, 0x87, 0xa4, 0x28, 0x92, 0x49, 0x91, 0xec, 
   0x7d, 0x0c, 0x69, 0x12, 0x58, 0x8f, 0xc3, 0xa5, 
   0x95, 0x2f, 0x2c, 0xf0, 0xff, 0xa2, 0x5e, 0x52, 
   0xfb, 0x8d, 0xe1, 0x96, 0xe7, 0x84, 0xc8, 0x31, 
   0xea, 0x4b, 0xae, 0xbb, 0xef, 0x63, 0x45, 0xed, 
   0x64, 0x6c, 0x8a, 0x03, 0xbf, 0xad, 0x37, 0xc4, 
   0xaf, 0xea, 0x13, 0x1f, 0x2b, 0x75, 0x15, 0xf4, 
   0x82, 0x79, 0x27, 0xc5, 0x2d, 0x36, 0x6d, 0xb9, 
   0x47, 0x24, 0xbc, 0xbc, 0x58, 0x91, 0x1a, 0xad, 
   0xf5, 0xda, 0xc9, 0x54, 0x00, 0x11, 0x52, 0xa9, 
   0x82, 0x45, 0x12, 0xdb, 0xc3, 0x66, 0x7d, 0x0f, 
   0x5d, 0xf9, 0x86, 0x10, 0x76, 0xa4, 0x67, 0x31, 
   0xe6, 0x8c, 0x5e, 0xd3, 0xad, 0xef, 0x54, 0x04, 
   0x1e, 0x51, 0x83, 0x2e, 0xfe, 0xd5, 0x46, 0x75, 
   0xfb, 0x4d, 0xa2, 0x81, 0xe4, 0x2f, 0x30, 0x2f, 
   0xff, 0x15, 0x36, 0x6e, 0x07, 0x2a, 0xd7, 0x71, 
   0x56, 0xd9, 0x38, 0x4d, 0xec, 0xc0, 0x6e, 0xa1, 
   0x82, 0x2b, 0xb2, 0xf1, 0xdf, 0xdd, 0x79, 0x15, 
   0x7a, 0xcc, 0x25, 0x49, 0x53, 0x79, 0xd6, 0x01, 
   0x30, 0x37, 0x81, 0x4b, 0x56, 0x6d, 0x76, 0x70, 
   0x87, 0x6c, 0x4f, 0x8f, 0x1e, 0xc9, 0xce, 0x7c, 
   0x53, 0x71, 0x83, 0x61, 0x7b, 0x03, 0xed, 0x2b, 
   0x5b, 0xc4, 0x32, 0x9e, 0x1e, 0xa5, 0xf7, 0xc8, 
   0xf6, 0x42, 0xff, 0xda, 0xde, 0x52, 0xa5, 0x2d, 
   0x5c, 0x96, 0xd6, 0x9e, 0xe5, 0x0d, 0xe9, 0x75, 
   0xc2, 0x40, 0x94, 0xb6, 0xbc, 0xb6, 0xe7, 0x52, 
   0x8c, 0x05, 0x67, 0xda, 0x97, 0xfc, 0xea, 0xc1, 
   0x1d, 0xe0, 0xcd, 0x05, 0x0e, 0xa2, 0x64, 0x6c, 
   0xe2, 0x56, 0x93, 0x68, 0xea, 0xcc, 0x6f, 0xfb, 
   0x23, 0x45, 0xc4, 0xe7, 0x78, 0xdf, 0x6b, 0x26, 
   0x7f, 0xd3, 0x2e, 0x27, 0x7d, 0xc1, 0x2e, 0x74, 
   0x39, 0x3d, 0x9c, 0x8c, 0xa4, 0x27, 0x0b, 0x8b, 
   0xad, 0xf5, 0x9f, 0x2a, 0xc8, 0x18, 0x12, 0xf1, 
   0x1b, 0x04, 0x5e, 0x83, 0x5a, 0xec, 0x86, 0xc8, 
   0xfc, 0x13, 0x45, 0xfb, 0xac, 0x03, 0x24, 0xf2, 
   0xce, 0x0f, 0x80, 0x7a, 0x54, 0xc6, 0x01, 0xd6, 
   0x71, 0x9b, 0x61, 0x49, 0x4a, 0x14, 0xca, 0x82, 
   0xae, 0x0d, 0x96, 0xe8, 0xcf, 0xb6, 0x78, 0xb1, 
   0x39, 0xfc, 0x34, 0xda, 0xb0, 0xe9, 0x59, 0x5c, 
   0x3d, 0xd9, 0x2e, 0xa8, 0x04, 0xc5, 0x78, 0x0d, 
   0x91, 0x13, 0x66, 0x57, 0x55, 0xc6, 0xcb, 0x23, 
   0x22, 0x1e, 0xbc, 0x4f, 0xb9, 0xb6, 0x2d, 0xe9, 
   0x1a, 0x8d, 0xa1, 0x9d, 0xc4, 0x5a, 0xfd, 0x5a, 
   0xc1, 0x45, 0x61, 0x4d, 0x2a, 0x09, 0x73, 0xf1, 
   0xee, 0xce, 0x98, 0xeb, 0x0e, 0xd3, 0x97, 0x14, 
   0x6c, 0x94, 0xbc, 0xd8, 0x1e, 0x74, 0x97, 0x45, 
   0x49, 0x60, 0x76, 0x58, 0xc0, 0x9f, 0x15, 0xf9, 
  };

  SshCipher cipher;
  unsigned char data[256];
  unsigned char ciphered[256];
  size_t datalen;
  unsigned int i, row, pos;
  unsigned int keylen;

  datalen = 8;
  keylen = 24;
  pos = 0;
  
  for (row = 0; row < 100; row++)
    {
      for (i = 0; i < datalen; i++)
        {
          data[i] = s_data[pos + i];
        }

      pos += datalen;
      
      if (ssh_cipher_allocate("3des-ecb",
                              key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        {
          printf("Failure.\n");
          exit(1);
        }
      
      ssh_cipher_transform(cipher, ciphered, data, datalen);

      for (i = 0; i < datalen; i++)
        {
          if (ciphered[i] != s_data[i + pos])
            {
              printf("Error!!!\n");
            }
        }
      pos += i;
      
      ssh_cipher_free(cipher);
    }
}

void test_3des_cipher(SshRandomState state)
{
  SshCipher cipher;
  unsigned char data[256];
  unsigned char ciphered[256];
  size_t datalen;
  unsigned int i, row;
  unsigned char key[24];
  size_t keylen;

  datalen = 8;
  keylen = 24;

  printf("unsigned char key[%d] = \n", keylen);

  printf("{");
  for (i = 0; i < keylen; i++)
    {
      key[i] = ssh_random_get_byte(state);
      printf("0x%02x, ", key[i]);
    }
  printf("};\n");

  printf("unsigned char data[%d] = \n", datalen * 2 * 100);
  printf("{");
  
  for (row = 0; row < 100; row++)
    {
      for (i = 0; i < datalen; i++)
        {
          data[i] = ssh_random_get_byte(state);
        }
      
      if (ssh_cipher_allocate("3des-ecb",
                              key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        {
          printf("Failure.\n");
          exit(1);
        }
      
      ssh_cipher_transform(cipher, ciphered, data, datalen);

      for (i = 0; i < datalen; i++)
        {
          printf("0x%02x, ", data[i]);
        }

      printf("\n");
      
      for (i = 0; i < datalen; i++)
        {
          printf("0x%02x, ", ciphered[i]);
        }
      printf("\n");
      
      ssh_cipher_free(cipher);
    }

  printf("};\n");
}
      
#endif

void cipher_random_tests(SshRandomState state)
{
  char *namelist = ssh_cipher_get_supported();
  const char *tmp_namelist = namelist;
  char *cipher_name = NULL;
  unsigned char *key;
  SshUInt32 keylen;
  unsigned char *buf;
  unsigned char *buf2;
  int i, len;
  TimeIt tmit;
  SshCipher cipher;

  while ((cipher_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      /* Cipher encryption & decryption tests. */

      /* Generate random key. */

      keylen = ssh_cipher_get_key_length(cipher_name);
      if (keylen == 0)
        {
          do
            {
              keylen = (SshUInt32)ssh_random_get_byte(state);
            }
          while (keylen == 0);
        }
      
      key = ssh_xmalloc(keylen);
      
      for (i = 0; i < keylen; i++)
        {
          key[i] = ssh_random_get_byte(state);
        }
      
      if (ssh_cipher_allocate(cipher_name,
                              key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s allocate failed.", cipher_name);

      len = 1024;
    retry:
      buf = ssh_xmalloc(len);
      buf2 = ssh_xmalloc(len);
      for (i = 0; i < len; i++)
        buf2[i] = i & 0xff;

      start_timing(&tmit);
      
      for (i = 0; i < 1024; i++)
        {
      
          if (ssh_cipher_transform(cipher, buf, buf2, len) != SSH_CRYPTO_OK)
            ssh_fatal("error: cipher %s transform failed.", cipher_name);
        }

      check_timing(&tmit);

      if (tmit.real_secs <= 1.0 && len < 10000000)
        {
          len *= 2;
          ssh_xfree(buf);
          ssh_xfree(buf2);
          printf("  - %s was too fast, retrying...\n", cipher_name);
          goto retry;
        }

      if (tmit.real_secs >= 1.0)
        printf("%s timed to encrypt at rate %f KBytes/sec.\n",
               cipher_name, ((double)len)/tmit.real_secs);
      else
        printf("  - timing could not be performed for %s.\n", cipher_name);

      
      
      ssh_cipher_free(cipher);

      if (ssh_cipher_allocate(cipher_name,
                              key, keylen,
                              FALSE, &cipher) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s allocate (2) failed.", cipher_name);

      start_timing(&tmit);
      
      for (i = 0; i < 1024; i++)
        {
          if (ssh_cipher_transform(cipher, buf2, buf, len) != SSH_CRYPTO_OK)
            ssh_fatal("error: cipher %s transform failed.", cipher_name);
        }

      check_timing(&tmit);

      if (tmit.real_secs <= 1.0 && len < 10000000)
        {
          len *= 2;
          ssh_xfree(buf);
          ssh_xfree(buf2);
          printf("  - %s was too fast, retrying...\n", cipher_name);
          goto retry;
        }

      if (tmit.real_secs >= 1.0)
        printf("%s timed to decrypt at rate %f KBytes/sec.\n",
               cipher_name, ((double)len)/tmit.real_secs);
      else
        printf("  - timing could not be performed for %s.\n", cipher_name);

      
      ssh_cipher_free(cipher);

      for (i = 0; i < len; i++)
        buf2[i] = (i & 0xff);

      if (ssh_cipher_allocate(cipher_name, key, keylen,
                              TRUE, &cipher) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s allocate failed.", cipher_name);
      
      if (ssh_cipher_transform(cipher, buf, buf2, len) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s failed to encrypt.", cipher_name);

      ssh_cipher_free(cipher);
      
      if (ssh_cipher_allocate(cipher_name, key, keylen,
                              FALSE, &cipher) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s allocate failed.", cipher_name);
      
      if (ssh_cipher_transform(cipher, buf2, buf, len) != SSH_CRYPTO_OK)
        ssh_fatal("error: cipher %s failed to encrypt.", cipher_name);

      ssh_cipher_free(cipher);
      
      for (i = 0; i < len; i++)
        {
          if (buf2[i] != (i & 0xff))
            {
              ssh_fatal("error: cipher %s data check failed on %dth byte.",
                    cipher_name, i);
            }
        }

      ssh_xfree(buf);
      ssh_xfree(buf2);
      ssh_xfree(key);
      ssh_xfree(cipher_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
    }

  ssh_xfree(namelist);
}

void cipher_static_tests()
{
  char cipher_name[256];
  unsigned char key[1024];
  unsigned char buf1[1024], buf2[1024];
  unsigned char iv[256];
  unsigned char *str;
  size_t len, keylen = 0, buf1_len = 0;
  SshCipher cipher = NULL;
  RFStatus status;
#define CIPHER_IGNORE 0
#define CIPHER_KEY    1
#define CIPHER_INPUT1 2
#define CIPHER_INPUT2 3
#define CIPHER_OUTPUT 4
  unsigned int state = CIPHER_IGNORE;

  status = ssh_t_read_init(TEST_SRC_PATH "/cipher.tests");
  if (status != RF_READ)
    ssh_fatal("error: cipher.tests could be not be opened.");

  while (status != RF_EMPTY)
    {
      status = ssh_t_read_token(&str, &len);
      switch (status)
        {
        case RF_LABEL:
          if (cipher != NULL)
            ssh_cipher_free(cipher);

          if (len > 255)
            ssh_fatal("error: cipher name too long.");

          memcpy(cipher_name, str, len);
          cipher_name[len] = '\0';

          if (ssh_cipher_supported(cipher_name))
            state = CIPHER_KEY;
          else
            {
              ssh_debug("cipher %s not supported", cipher_name);
              state = CIPHER_IGNORE;
            }
          break;
        case RF_HEX:
        case RF_ASCII:
          switch (state)
            {
            case CIPHER_KEY:
              if (len < ssh_cipher_get_key_length(cipher_name))
                ssh_fatal("error: key too short.");

              if (len > 1024)
                ssh_fatal("error: key too  long.");
              
              memcpy(key, str, len);
              keylen = len;
              
              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      TRUE, &cipher) != SSH_CRYPTO_OK)
                ssh_fatal("error: cipher allocate %s failed.", cipher_name);

              state = CIPHER_INPUT1;
              break;
            case CIPHER_INPUT1:
              if (len != ssh_cipher_get_block_length(cipher))
                ssh_fatal("error: iv too long for %s.", cipher_name);
              
              memcpy(iv, str, len);
              ssh_cipher_set_iv(cipher, str);
              
              state = CIPHER_INPUT2;
              break;
            case CIPHER_INPUT2:
              if (len > 1024)
                ssh_fatal("error: input too long.");

              memcpy(buf1, str, len);
              buf1_len = len;
              
              if (ssh_cipher_transform(cipher, buf2, buf1, buf1_len)
                  != SSH_CRYPTO_OK)
                ssh_fatal("error: in transform %s.", cipher_name);

              state = CIPHER_OUTPUT;
              break;
            case CIPHER_OUTPUT:
              if (len != buf1_len)
                ssh_fatal("error: incompatible input/output lengths.");

              if (memcmp(buf2, str, len) != 0)
                ssh_fatal("error: cipher %s failed (1).", cipher_name);

              ssh_cipher_free(cipher);

              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      FALSE, &cipher) != SSH_CRYPTO_OK)
                ssh_fatal("error: cipher allocate %s failed.", cipher_name);

              ssh_cipher_set_iv(cipher, iv);
              
              if (ssh_cipher_transform(cipher, buf2, str, len)
                  != SSH_CRYPTO_OK)
                ssh_fatal("error: in transform %s.", cipher_name);

              if (memcmp(buf2, buf1, buf1_len) != 0)
                ssh_fatal("error: cipher %s failed (2).", cipher_name);

              if (ssh_cipher_allocate(cipher_name,
                                      key, keylen,
                                      TRUE, &cipher) != SSH_CRYPTO_OK)
                ssh_fatal("error: cipher allocate %s failed.", cipher_name);

              ssh_cipher_set_iv(cipher, iv);
              
              state = CIPHER_INPUT1;
              break;
            case CIPHER_IGNORE:
              break;
            default:
              ssh_fatal("error: unknown state (%d).", state);
              break;
            }
        case RF_EMPTY:
          break;
        default:
          ssh_fatal("error: file error (%d).", status);
          break;
        }
    }

  ssh_t_close();

  if (cipher)
    ssh_cipher_free(cipher);
}

void cipher_static_tests_do(SshRandomState state)
{
  char *namelist = ssh_cipher_get_supported();
  const char *tmp_namelist = namelist;
  char *cipher_name = NULL;
  unsigned char *key;
  size_t keylen;
  unsigned char buf[1024];
  unsigned char buf2[1024];
  unsigned char iv[256];
  unsigned char *tmp;
  int i, j, k, input_length;
  SshCipher cipher;
  RFStatus status;

  status = ssh_t_write_init("cipher.tests.created");
  if (status != RF_WRITE)
    ssh_fatal("error: could not create cipher.tests.created.");

  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  tmp = (unsigned char *) TEST_SRC_PATH "/cipher.tests";
  ssh_t_write_token(RF_COMMENT, tmp, strlen((char *) tmp));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  
  while ((cipher_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      /* Cipher encryption & decryption tests. */

      ssh_t_write_token(RF_COMMENT, (unsigned char *) cipher_name,
                        strlen(cipher_name));

      for (k = 0; k < 16; k++)
        {
          /* Generate random key. */
          
          keylen = ssh_cipher_get_key_length(cipher_name);
          if (keylen == 0)
            {
              do
                {
                  keylen = ((SshUInt32)ssh_random_get_byte(state)) & 31;
                }
              while (keylen == 0);
            }
          
          key = ssh_xmalloc(keylen);
      
          for (i = 0; i < keylen; i++)
            {
              key[i] = ssh_random_get_byte(state);
            }
      
          if (ssh_cipher_allocate(cipher_name,
                                  key, keylen,
                                  TRUE, &cipher) != SSH_CRYPTO_OK)
            ssh_fatal("error: cipher %s allocate failed.", cipher_name);

          ssh_t_write_token(RF_LABEL, (unsigned char *) cipher_name,
                            strlen(cipher_name));
          ssh_t_write_token(RF_HEX, key, keylen);
          ssh_t_write_token(RF_LINEFEED, NULL, 0);

          input_length = (ssh_cipher_get_block_length(cipher) < 8
                          ? 8 : ssh_cipher_get_block_length(cipher));
          
          for (j = 0; j < 8; j++)
            {
              for (i = 0; i < input_length; i++)
                buf2[i] = ssh_random_get_byte(state);

              for (i = 0; i < ssh_cipher_get_block_length(cipher); i++)
                iv[i] = ssh_random_get_byte(state);

              ssh_cipher_set_iv(cipher, iv);

              ssh_t_write_token(RF_HEX, iv,
                                ssh_cipher_get_block_length(cipher));
              ssh_t_write_token(RF_HEX, buf2, input_length);

              if (ssh_cipher_transform(cipher, buf,
                                       buf2, input_length) != SSH_CRYPTO_OK)
                ssh_fatal("error: cipher %s transform failed.", cipher_name);

              ssh_t_write_token(RF_HEX, buf, input_length);
              ssh_t_write_token(RF_LINEFEED, NULL, 0);
            }

          ssh_cipher_free(cipher);
        }
      
      ssh_xfree(key);
      ssh_xfree(cipher_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
    }

  tmp = (unsigned char *) TEST_SRC_PATH "/cipher.tests";
  ssh_t_write_token(RF_LINEFEED, NULL, 0);
  ssh_t_write_token(RF_COMMENT, tmp, strlen((char *) tmp));
  ssh_t_write_token(RF_LINEFEED, NULL, 0);

  /* Close and flush the stream. */
  ssh_t_close();
  
  ssh_xfree(namelist);
}

void test_cipher(SshRandomState state, int flag)
{
  if (flag & 0x2)
    {
      printf(" - random tests (with timing).\n");
      cipher_random_tests(state);
    }
  if (flag & 0x8)
    {
      printf(" - generating static test cases.\n");
      cipher_static_tests_do(state);
    }
  if (flag & 0x4)
    {
      printf(" - running static tests.\n");
      cipher_static_tests();
    }
}


/**************************** PKCS tests *******************************/


void my_progress_func(SshCryptoProgressID id,
                      unsigned int time_value, void *context)
{
  switch (id)
    {
    case SSH_CRYPTO_PRIME_SEARCH:
      printf("\rPrime search: %dth value.", time_value);
      fflush(stdout);
      break;
    default:
      printf("\rOperation %d: %dth value.", id, time_value);
      fflush(stdout);
      break;
    }
}

void pkcs_random_tests(SshRandomState state)
{
  char *namelist = ssh_public_key_get_supported();
  const char *tmp_namelist = namelist;
  char *pkcs_name = NULL;
  int i, cnt;
  size_t len;
  static int use_randomizers = 0;
  int size = 1024;
  char *passphrase = "ssh-communications-security-finland-passphrase";
  char *cipher_name = "blowfish-cfb";

  /* Test pointers. */
  unsigned char *a, *b, *c, *d;
  size_t a_len, b_len, c_len, d_len;

  TimeIt tmit;
  
  SshPublicKey public_key;
  SshPrivateKey private_key;

  void *secret_one, *secret_two;
  SshPkGroup pk_group_one, pk_group_two;

  /* Register a progress monitoring function. */
  ssh_crypto_library_register_progress_func(my_progress_func,
                                            NULL);
  
  while ((pkcs_name = ssh_name_list_get_name(tmp_namelist)) != NULL)
    {
      /* Allocation of the private key. */

      printf("Public key method %s in testing.\n", pkcs_name);

      start_timing(&tmit);

      if (memcmp(pkcs_name, (const unsigned char *)"ec-", 3) != 0)
        {
          if (ssh_private_key_generate(state, &private_key,
                                       pkcs_name,
                                       SSH_PKF_SIZE, size,
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            ssh_fatal("error: pkcs %s generate keys failed.", pkcs_name);
        }
      else
      if (memcmp(pkcs_name, (const unsigned char *)"ec-modp", 7) == 0)
        {
          if (ssh_private_key_generate(state, &private_key,
                                       pkcs_name,
                                       SSH_PKF_PREDEFINED_GROUP,
                                       "ssh-ec-modp-curve-155bit-1",
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            ssh_fatal("error: pkcs %s generate keys failed.", pkcs_name);
        }
      else
      if (memcmp(pkcs_name, (const unsigned char *)"ec-gf2n", 7) == 0)
        {
          if (ssh_private_key_generate(state, &private_key,
                                       pkcs_name,
                                       SSH_PKF_PREDEFINED_GROUP,
                                       "ssh-ec-gf2n-curve-185bit-2",
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            ssh_fatal("error: pkcs %s generate keys failed.", pkcs_name);
        }
      else
        ssh_fatal("error: pkcs %s key type did not match.", pkcs_name);

      check_timing(&tmit);

      printf("\n%s's key generation executed in %f seconds.\n",
             pkcs_name, tmit.real_secs);
      
      printf("Private key generated.\n");
      
      public_key = ssh_private_key_derive_public_key(private_key);

      printf("Public key derived.\n");
      
      /* Export and import tests. */
        
      if (ssh_public_key_export(public_key, &a, &a_len) != SSH_CRYPTO_OK)
        ssh_fatal("error: public key %s export failed.", pkcs_name);

      printf("Public key exported.\n");
      
      if (ssh_private_key_export_with_passphrase(private_key,
                                                 cipher_name,
                                                 passphrase,
                                                 state,
                                                 &b, &b_len) != SSH_CRYPTO_OK)
        ssh_fatal("error: private key %s export failed.", pkcs_name);

      printf("Private key exported with passphrase.\n");
      
      ssh_public_key_free(public_key);
      ssh_private_key_free(private_key);

      printf("Both keys were freed.\n");

      if (ssh_public_key_import(a, a_len, &public_key) != SSH_CRYPTO_OK)
        ssh_fatal("error: public key %s import failed.", pkcs_name);

      printf("Public key imported.\n");
      
      if (ssh_private_key_import_with_passphrase(b,
                                                 b_len,
                                                 passphrase,
                                                 &private_key)
          != SSH_CRYPTO_OK)
        ssh_fatal("error: private key %s import failed.", pkcs_name);

      printf("Private key imported with passphrase.\n");
      
      ssh_xfree(a);
      ssh_xfree(b);

      /* Testing of public key groups. */

      pk_group_one = ssh_public_key_derive_pk_group(public_key);
      if (pk_group_one)
        {
          printf("Testing public key group import/export. \n");

          if (ssh_pk_group_export(pk_group_one,
                                  &a, &a_len) != SSH_CRYPTO_OK)
            ssh_fatal("error: cannot export public key group.");

          ssh_pk_group_free(pk_group_one);
          
          if (ssh_pk_group_import(a, a_len,
                                  &pk_group_one) != SSH_CRYPTO_OK)
            ssh_fatal("error: cannot import public key group.");

          ssh_xfree(a);
          printf("Import/export runned.\n");

          /* Randomizers. */
          
          if (use_randomizers)
            {
              printf("Generating randomizers.\n");
              for (i = 0; i < 20; i++)
                ssh_pk_group_generate_randomizer(pk_group_one, state);

              printf("Exporting randomizers.\n");

              if (ssh_pk_group_count_randomizers(pk_group_one) != 20)
                ssh_fatal("error: generated incorrect amount of randomizers.");
              
              if (ssh_pk_group_export_randomizers(pk_group_one,
                                                  &a, &a_len) != SSH_CRYPTO_OK)
                ssh_fatal("error: cannot export randomizers.");

              if (ssh_pk_group_import_randomizers(pk_group_one,
                                                  a, a_len)
                  != SSH_CRYPTO_OK)
                ssh_fatal("error: cannot import randomizers.");

              ssh_xfree(a);
            }
          
          ssh_pk_group_free(pk_group_one);
        }
      
      /* Encryption tests. */

      printf("Encryption tests.\n");
      
      a_len = ssh_public_key_max_encrypt_input_len(public_key);
      if (a_len != 0)
        {
          b_len = ssh_public_key_max_encrypt_output_len(public_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;
          
          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);
          
          for (i = 0; i < a_len; i++)
            {
              a[i] = i & 0xff;
            }

          cnt = PKCS_CNT;
          
        retry1:
          
          start_timing(&tmit);

          for (i = 0; i < cnt; i++)
            {
              if (ssh_public_key_encrypt(public_key, a, a_len, b, b_len, &len,
                                         state) != SSH_CRYPTO_OK)
                ssh_fatal("error: pkcs %s encryption error.", pkcs_name);
            }
          
          check_timing(&tmit);

          if (tmit.real_secs <= 1.0 && cnt < 100000)
            {
              cnt *= 2;
              printf("  - %s encrypt was too fast, retrying...\n",
                     pkcs_name);
              goto retry1;
            }

          if (tmit.real_secs >= 1.0)
            printf("%s timed to encrypt at rate %f times/sec (%f ms/encrypt).\n",
                   pkcs_name, ((double)cnt)/tmit.real_secs,
                   tmit.real_secs / (double) cnt * 1000);
          else
            printf("  - timing could not be performed for %s.\n", pkcs_name);
          
          printf("Encrypted with public key.\n");
          
          if (len > b_len)
            ssh_fatal("error: pkcs %s outputed ciphertext too long.",
                      pkcs_name);
          
          if (len > ssh_private_key_max_decrypt_input_len(private_key))
            ssh_fatal("error: pkcs %s ciphertext length incompatible.",
                      pkcs_name);
          
          c_len = ssh_private_key_max_decrypt_output_len(private_key);
          if (c_len == -1)
            c_len = b_len;
          c = ssh_xmalloc(c_len);
          
          cnt = PKCS_CNT;
          
        retry2:
          
          start_timing(&tmit);

          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_decrypt(private_key,
                                          b, b_len, c,
                                          c_len, &len) != SSH_CRYPTO_OK)
                ssh_fatal("error: pkcs %s decryption error.", pkcs_name);
              
            }
          
          check_timing(&tmit);
          
          if (tmit.real_secs <= 1.0 && cnt < 100000)
            {
              cnt *= 2;
              printf("  - %s decrypt was too fast, retrying...\n",
                     pkcs_name);
              goto retry2;
            }

          if (tmit.real_secs >= 1.0)
            printf("%s timed to decrypt at rate %f times/sec (%f ms/decrypt).\n",
                   pkcs_name, ((double)cnt)/tmit.real_secs,
                   tmit.real_secs / (double) cnt * 1000);
          else
            printf("  - timing could not be performed for %s.\n", pkcs_name);
          
          printf("Decrypted with the private key.\n");
      
          if (len > c_len)
            ssh_fatal("error: pkcs %s outputed plaintext too long.",
                      pkcs_name);
          
          if (len != a_len)
            ssh_fatal("error: pkcs %s plaintext length incompatible.",
                      pkcs_name);
          
          ssh_xfree(b);
          ssh_xfree(a);
          
          c_len = len;

          for (i = 0; i < c_len; i++)
            {
              if (c[i] != (i & 0xff))
                {
                  ssh_fatal("error: pkcs %s decryption failed.", pkcs_name);
                }
            }
          ssh_xfree(c);
        }
      else
        {
          printf("Method not capable for encryption.\n");
        }
          
      /* Signature tests. */

      printf("Signature tests.\n");

      /* Randomizers! */
      
      a_len = ssh_private_key_max_signature_input_len(private_key);
      if (a_len != 0)
        {
          b_len = ssh_private_key_max_signature_output_len(private_key);

          if (a_len == -1)
            a_len = 1024;
          if (b_len == -1)
            b_len = a_len;
          
          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);
          
          for (i = 0; i < a_len; i++)
            {
              a[i] = i & 0xf;
            }
          
          cnt = PKCS_CNT;
          
        retry3:
          
          start_timing(&tmit);
          
          for (i = 0; i < cnt; i++)
            {
              if (ssh_private_key_sign(private_key, a, a_len,
                                       b, b_len, &len, state) != SSH_CRYPTO_OK)
                ssh_fatal("error: pkcs %s sign error.", pkcs_name);
            }
          
          check_timing(&tmit);
          
          if (tmit.real_secs <= 1.0 && cnt < 100000)
            {
              cnt *= 2;
              printf("  - %s signing was too fast, retrying...\n", pkcs_name);
              goto retry3;
            }

          if (tmit.real_secs >= 1.0)
            printf("%s signs at rate %f times/sec (%f ms/sign).\n", pkcs_name,
                   ((double)cnt)/tmit.real_secs,
                   tmit.real_secs / (double) cnt * 1000);
          else
            printf("  - timing could not be performed for %s.\n", pkcs_name);
          
          printf("Signed with the private key.\n");
          
          if (len > b_len)
            ssh_fatal("error: pkcs %s outputed signature too long.",
                      pkcs_name);

          cnt = PKCS_CNT;
          
        retry4:

          start_timing(&tmit);
          
          for (i = 0; i < cnt; i++)
            {
              if (ssh_public_key_verify_signature(public_key,
                                                  b, len,
                                                  a, a_len) == FALSE)
                ssh_fatal("error: %s signature not correct.", pkcs_name);
            }
          
          check_timing(&tmit);

          if (tmit.real_secs <= 1.0 && cnt < 100000)
            {
              cnt *= 2;
              printf("  - %s signing verifying was too fast, retrying...\n",
                     pkcs_name);
              goto retry4;
            }

          if (tmit.real_secs >= 1.0)
            printf("%s verifies signatures at rate %f times/sec (%f ms/verify).\n",
                   pkcs_name, ((double)cnt)/tmit.real_secs,
                   tmit.real_secs / (double) cnt * 1000);
          else
            printf("  - timing could not be performed for %s.\n",
                   pkcs_name);
          
          printf("Verified with the public key.\n");
          
          ssh_xfree(a);
          ssh_xfree(b);
        }
      else
        printf("Method not capable of signing.\n");

      pk_group_one = ssh_public_key_derive_pk_group(public_key);
      pk_group_two = ssh_private_key_derive_pk_group(private_key);

      if (pk_group_one && pk_group_two)
        {
          printf("Derived groups.\n");

          a_len =
            ssh_pk_group_diffie_hellman_setup_max_output_length(pk_group_one);
          b_len =
            ssh_pk_group_diffie_hellman_setup_max_output_length(pk_group_two);

          /* Not capable for diffie hellman. */
          if (a_len == 0 || b_len == 0)
            {
              printf("Method not capable of performing Diffie-Hellman.\n");
              goto end_diffie_hellman;
            }
              
          a = ssh_xmalloc(a_len);
          b = ssh_xmalloc(b_len);

          if (ssh_pk_group_diffie_hellman_setup(pk_group_one,
                                                &secret_one,
                                                a, a_len,
                                                &len, state) != SSH_CRYPTO_OK)
            ssh_fatal("error: could not do Diffie-Hellman setup. (1)");

          if (len != a_len)
            ssh_fatal("error: len != a_len!");

          if (ssh_pk_group_diffie_hellman_setup(pk_group_two,
                                                &secret_two,
                                                b, b_len,
                                                &len, state) != SSH_CRYPTO_OK)
            ssh_fatal("error: could not do Diffie-Hellman setup. (2)");

          c_len =
            ssh_pk_group_diffie_hellman_agree_max_output_length(pk_group_one);
          d_len =
            ssh_pk_group_diffie_hellman_agree_max_output_length(pk_group_two);

          if (c_len == 0 || d_len == 0)
            ssh_fatal("error: could not continue to agree.");
          
          c = ssh_xmalloc(c_len);
          d = ssh_xmalloc(d_len);
          
          if (ssh_pk_group_diffie_hellman_agree(pk_group_one,
                                                secret_one,
                                                b, b_len,
                                                c, c_len,
                                                &len) != SSH_CRYPTO_OK)
            ssh_fatal("error: could not do Diffie-Hellman agree. (1)");

          if (len != c_len)
            ssh_fatal("error: minor detail.\n");
          
          if (ssh_pk_group_diffie_hellman_agree(pk_group_two,
                                                secret_two,
                                                a, a_len,
                                                d, d_len,
                                                &len) != SSH_CRYPTO_OK)
            ssh_fatal("error: could not do Diffie-Hellman agree. (2)");

          if (d_len != len)
            ssh_fatal("error: minor detail.\n");
          
          if (d_len != c_len)
            ssh_fatal("error: not correct agreement.\n");

          if (memcmp(d, c, d_len) != 0)
            ssh_fatal("error: incorrect result.\n");

          printf("Diffie-Hellman key agreement was a success.\n");
          ssh_xfree(a);
          ssh_xfree(b);
          ssh_xfree(c);
          ssh_xfree(d);

          ssh_pk_group_free(pk_group_one);
          ssh_pk_group_free(pk_group_two);

        end_diffie_hellman:
          ;                     /* OSF cc cannot compile this file if this
                                   empty statement is not here. */
        }
      else
        printf("Method not capable of extracting groups.\n");
      
      /* Free contexts. */
      
      ssh_public_key_free(public_key);
      ssh_private_key_free(private_key);
      
      ssh_xfree(pkcs_name);
      tmp_namelist = ssh_name_list_step_forward(tmp_namelist);
      
      printf("\n");
    }

  /* Remove progress monitoring functions from use. */
  ssh_crypto_library_register_progress_func(NULL, NULL);
  
  use_randomizers = 1 - use_randomizers;
  
  ssh_xfree(namelist);
}

void test_pkcs(SshRandomState state, int flag)
{
  printf(" - random tests (with timing).\n");
  pkcs_random_tests(state);
}

/****************************** ECP Test **********************************/

void test_ecp(SshRandomState state)
{
  return;
}


/****************************** Main ***************************************/

/* Main function that calls all the tests above. */

int main(int argc, char *argv[])
{
  SshRandomState state;
  int i, not, do_static, test_rnd, test_static;
  int rnd_flag, hash_flag, mac_flag, cipher_flag, pkcs_flag;
  
#if 0
  /* This short piece of test code is for our previous SHA-1 bug. It was
     cunning enough not to show up in NIST examples (even partitioned).
     However the following test detects it.

     Bug can be detected by having 128 bytes of data to be hashed. This
     data is divided in two parts first part having 1 byte and rest
     127 bytes. These bytes should not all be the same.

     Then update the hash context with both parts in correct order (first
     the 1 byte and then the rest 127 bytes). Compare this with the
     hash output of straigh hashing of 128 original bytes. If result
     is not equal then this error (or some other) was detected.
     */

  SshHash hash;
  unsigned char digest[128];

  
  ssh_hash_allocate("sha1", &hash);

  ssh_hash_reset(hash);
  for (i = 0; i < 128; i++)
    digest[i] = 0;
  digest[127] = 1;
  
  ssh_hash_update(hash, digest, 1);
  ssh_hash_update(hash, digest + 1, 127);

  ssh_hash_final(hash, digest);

  ssh_hash_reset(hash);
  
  for (i = 0; i < 20; i++)
    printf("%02x", digest[i]);
  printf("\n");

  for (i = 0; i < 128; i++)
    digest[i] = 0;
  digest[127] = 1;

  ssh_hash_update(hash, digest, 128);

  ssh_hash_final(hash, digest);

  for (i = 0; i < 20; i++)
    printf("%02x", digest[i]);
  printf("\n");
  
  ssh_hash_free(hash);

  exit(1);
  
#endif
  
  rnd_flag = 1;
  hash_flag = 7;
  mac_flag = 7;
  cipher_flag = 7;
  pkcs_flag = 1;

  /* Doing some argument checking. */
  if (argc > 1)
    {
      argv++;
      argc--;

      not = 1;
      do_static = 0;
      test_rnd = 1;
      test_static = 1;
      
      while (argc--)
        {
          for (i = 0; (*argv)[i]; i++)
            {
              switch ((*argv)[i])
                {
                  /* Operands. */
                case '!':
                  not ^= 1;
                  break;
                case 'D':
                  do_static = not;
                  break;
                case 'R':
                  test_rnd = not;
                  break;
                case 'S':
                  test_static = not;
                  break;

                  /* tests. */
                case 'r':
                  rnd_flag = not;
                  break;
                case 'h':
                  hash_flag = not |
                    (test_rnd << 1) | (test_static << 2) | (do_static << 3);
                  break;
                case 'm':
                  mac_flag = not |
                    (test_rnd << 1) | (test_static << 2) | (do_static << 3);
                  break;
                case 'c':
                  cipher_flag = not |
                    (test_rnd << 1) | (test_static << 2) | (do_static << 3);
                  break;
                case 'p':
                  pkcs_flag = not;
                  break;
                default:
                  break;
                }
            }
        }
    }
  
  printf("\nCrypto Library testing.\n");
  
  state = ssh_random_allocate();

  if (rnd_flag & 0x1)
    {
      printf("\nRandom number test...\n");
      test_random(state, rnd_flag);
    }
   if (hash_flag & 0x1)
     {
       printf("\nHash test...\n");
       for (i = 0; i < 2; i++)
         test_hash(state, hash_flag);
     }
   if (mac_flag & 0x1)
     {
       printf("\nMac test...\n");
       for (i = 0; i < 2; i++)
         test_mac(state, mac_flag);
     }
  if (cipher_flag & 0x1)
    {
      printf("\nCipher test...\n");
      for (i = 0; i < 2; i++)
        test_cipher(state, cipher_flag);
    }
  if (pkcs_flag & 0x1)
    {
      printf("\nPkcs test...\n");
      for (i = 0; i < 2; i++)
        test_pkcs(state, pkcs_flag);
    }
  
  ssh_random_free(state);
  exit(0);
}
      
