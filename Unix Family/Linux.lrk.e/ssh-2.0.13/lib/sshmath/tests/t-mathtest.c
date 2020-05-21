/*

  t-mathtest.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Apr 29 02:10:22 1998 [mkojo]

  Testing utility for math libraries. This program tries as many cases
  as possible to ensure that the math libraries are working correctly.

  Nevertheless, every application that uses these libraries should
  be tested thoroughly after changes to math libraries. This is because,
  although test here are reasonably good, they are not perfect. Also
  there might be changes to things that are "undocumented" but which
  previously worked.

  */

/*
 * $Id: t-mathtest.c,v 1.18 1999/05/04 02:19:56 kivinen Exp $
 * $Log: t-mathtest.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h"
#include "timeit.h"
#include "sieve.h"

/* Printing of different types to the screen, these are helpful when
   trying to figure out what was wrong. And also, sometimes to compare
   results with other systems. */

void print_int(char *str, SshInt *op)
{
  char *mstr;

  mstr = ssh_mp_get_str(NULL, 10, op);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);
}

void print_mont(char *str, SshIntModQ *op)
{
  char *mstr;
  SshInt a;

  ssh_mp_init(&a);
  ssh_mp_set_mpm(&a, op);

  mstr = ssh_mp_get_str(NULL, 10, &a);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);

  ssh_mp_clear(&a);
}

int check_mod(SshIntModQ *b, SshInt *a)
{
  SshInt t;
  int rv;
  
  ssh_mp_init(&t);
  ssh_mp_set_mpm(&t, b);
  rv = ssh_mp_cmp(a, &t);
  ssh_mp_clear(&t);
  return rv;
}

void my_rand_mod(SshIntModQ *a, SshInt *b, int bits)
{
  int n = random() % bits;
  ssh_mp_rand(b, n);
  ssh_mpm_set_mp(a, b);
}

void true_rand(SshInt *op, int bits)
{
  ssh_mp_rand(op, random() % bits);

  /* Occasionally make also negative. */
  if (random() & 0x1)
    ssh_mp_neg(op, op);
}

void test_int(int flag, int bits)
{
  SshInt a, b, c, d, e, f;
  int j, k, i, l;

  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&d);
  ssh_mp_init(&e);
  ssh_mp_init(&f);

  printf(" * addition/subtraction test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);

      ssh_mp_sub(&c, &a, &b);
      ssh_mp_add(&d, &c, &b);
      if (ssh_mp_cmp(&d, &a) != 0)
        {
          printf("error: subtraction/addition failed.\n");
          print_int("a = ", &a);
          print_int("a' = ", &d);
          exit(1);
        }
    }

  printf(" * addition/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mp_set_ui(&b, 0);
      k = random() % 1000;
      for (i = 0; i < k; i++)
        ssh_mp_add(&b, &b, &a);
      ssh_mp_mul_ui(&c, &a, k);
      if (ssh_mp_cmp(&c, &b) != 0)
        {
          printf("error: addition/multiplication failed.\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          printf("k = %u\n", k);
          exit(1);
        }
    }

  printf(" * subtraction/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mp_set_ui(&b, 0);
      k = random() % 1000;
      for (i = 0; i < k; i++)
        ssh_mp_sub(&b, &b, &a);
      ssh_mp_neg(&c, &a);
      ssh_mp_mul_ui(&c, &c, k);
      if (ssh_mp_cmp(&c, &b) != 0)
        {
          printf("error: subtraction/multiplication failed.\n");
          print_int("a = ", &a);
          print_int("b = ", &b);
          print_int("c = ", &c);
          printf("k = -%u\n", k);
          exit(1);
        }
    }
  
  printf(" * division test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&b, 0) == 0 ||
          ssh_mp_cmp_ui(&a, 0) == 0)
        continue;
      ssh_mp_mul(&c, &a, &b);
      ssh_mp_div(&d, &e, &c, &b);
      ssh_mp_div(&e, &f, &c, &a);

      if (ssh_mp_cmp(&d, &a) != 0 ||
          ssh_mp_cmp(&e, &b) != 0)
        {
          printf("error: division/multiplication failed.\n");

          print_int("c = ", &c);
          print_int("a = ", &a);
          print_int("a' = ", &d);
          print_int("b = ", &b);
          print_int("b' = ", &e);
          exit(1);
        }
    }

  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&b, 0) == 0)
        continue;

      ssh_mp_div(&c, &d, &a, &b);
      ssh_mp_mul(&e, &c, &b);
      ssh_mp_add(&e, &e, &d);

      if (ssh_mp_cmp(&e, &a) != 0)
        {
          printf("error: division/multiplication failed (in second test).\n");
          print_int("a = ", &a);
          print_int("a' = ", &e);
          exit(1);
        }
    }

  printf(" * multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mp_mul(&b, &a, &a);
      ssh_mp_square(&c, &a);

      if (ssh_mp_cmp(&c, &b) != 0)
        {
          printf("error: multiplication/squaring failed.\n");
          ssh_mp_dump(&a);
          ssh_mp_dump(&b);
          ssh_mp_dump(&c);
          
          print_int("a*a = ", &b);
          ssh_mp_dump(&b);
          print_int("a^2 = ", &c);
          ssh_mp_dump(&c);
          exit(1);
        }
    }

  printf(" * multiplication/gcd tests.\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&a, 0) == 0 ||
          ssh_mp_cmp_ui(&b, 0) == 0)
        continue;
      
      /* Make positive. */
      ssh_mp_abs(&a, &a);
      ssh_mp_abs(&b, &b);
      
      ssh_mp_mul(&c, &a, &b);
      ssh_mp_gcd(&d, &c, &a);
      ssh_mp_gcd(&e, &c, &b);

      if (ssh_mp_cmp(&d, &a) != 0 ||
          ssh_mp_cmp(&e, &b) != 0)
        {
          printf("error: multiplication/gcd failed.\n");
          print_int("d = ", &d);
          print_int("a = ", &a);
          print_int("e = ", &e);
          print_int("b = ", &b);
          exit(1);
        }
    }

  printf(" * squaring test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mp_square(&b, &a);
      ssh_mp_sqrt(&c, &b);

      ssh_mp_abs(&a, &a);
      
      if (ssh_mp_cmp(&a, &c) != 0)
        {
          printf("error: square root/squaring failed.\n");
          print_int("a = ", &a);
          print_int("a' = ", &c);
          exit(1);
        }
    }

  printf(" * exponentiation test\n");
  for (j = 0; j < 10; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
        continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
        ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      ssh_mp_mod(&b, &b, &a);
      ssh_mp_set(&c, &b);
      
      for (i = 1; i < 100; i++)
        {
          ssh_mp_set_ui(&e, i);
          ssh_mp_powm_ui(&d, k, &e, &a);
          if (ssh_mp_cmp(&d, &c) != 0)
            {
              printf("error: powm ui/multiplication failed.\n");
              print_int("mod = ", &a);
              printf("g   = %u\n", k);
              printf("exp = %u\n", i);
              print_int("1   = ", &d);
              print_int("2   = ", &c);
              exit(1);
            }

          ssh_mp_mul(&c, &c, &b);
          ssh_mp_mod(&c, &c, &a);
        }
    }

  printf(" * full exponentiation test\n");
  for (j = 0; j < 10; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
        continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
        ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      ssh_mp_mod(&b, &b, &a);
      ssh_mp_set(&c, &b);
      
      for (i = 1; i < 100; i++)
        {
          ssh_mp_set_ui(&e, i);
          ssh_mp_powm(&d, &b, &e, &a);
          if (ssh_mp_cmp(&d, &c) != 0)
            {
              printf("error: powm/multiplication failed.\n");
              print_int("mod = ", &a);
              print_int("g   = ", &b);
              print_int("exp = ", &e);
              print_int("1   = ", &d);
              print_int("2   = ", &c);
              exit(1);
            }

          ssh_mp_mul(&c, &c, &b);
          ssh_mp_mod(&c, &c, &a);
        }
    }
  
  for (j = 0; j < 100; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
        continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
        ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      true_rand(&e, bits);
      
      ssh_mp_powm(&c, &b, &e, &a);
      ssh_mp_powm_ui(&d, k, &e, &a);

      if (ssh_mp_cmp(&c, &d) != 0)
        {
          printf("error: powm/powm_ui failed!\n");
          print_int("mod = ", &a);
          print_int("exp = ", &e);
          print_int("g   = ", &b);
          print_int("1   = ", &c);
          print_int("2   = ", &d);

          exit(1);
        }
    }

  printf(" * kronecker-jacobi-legendre symbol tests\n");
  for (j = 0; j < 100; j++)
    {
      static int table[100] =
      {1,1,1,1,-1,1,1,1,1,1,-1,-1,1,1,-1,1,1,1,-1,1,1,1,1,-1,1,-1,-1,
       1,-1,1,1,-1,-1,1,1,1,-1,1,-1,-1,1,1,1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,1,1,-1,-1,-1,1,-1,1,1,-1,1,-1,-1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,-1,1,-1,1,1,1,1,1,-1,1,1,1,1,1,1,1,-1,-1};
      ssh_mp_set_ui(&a, j + 3);
      ssh_mp_set_ui(&b, 7919);

      if (ssh_mp_kronecker(&a, &b) != table[j])
        {
          printf("error: kronecker-jacobi-legendre symbol failed.\n");
          print_int(" a =", &a);
          print_int(" b =", &b);
          printf(" assumed %d got %d\n",
                 table[j], ssh_mp_kronecker(&a, &b));
          exit(1);
        }
    }
  
  if (flag)
    {
      printf(" * prime tests\n");
      for (j = 0; j < 10; j++)
        {
          printf("    - searching... [%u bit prime]\n", bits);
          true_rand(&a, bits);
          ssh_mp_abs(&a, &a);

          if (ssh_mp_next_prime(&a, &a) == FALSE)
            continue;

          printf("    - probable prime found\n");
          print_int("      =", &a);
                  
          printf("    - testing modular sqrt\n");
          for (l = 0; l < 10; l++)
            {
              true_rand(&b, bits);
              ssh_mp_abs(&b, &b);
              
              if (ssh_mp_mod_sqrt(&d, &b, &a) == FALSE)
                continue;
              ssh_mp_mod(&b, &b, &a);
              ssh_mp_square(&c, &d);
              ssh_mp_mod(&c, &c, &a);
              if (ssh_mp_cmp(&c, &b) != 0)
                {
                  printf("error: modular sqrt failed.\n");
                  print_int(" b =", &b);
                  print_int(" c =", &c);
                  print_int(" d =", &d);
                  printf(" Kronecker says: %d\n",
                         ssh_mp_kronecker(&b, &a));
                  exit(1);
                }
            }
        }
    }

  if (flag)
    {
      printf(" * square tests\n");
      for (j = 0; j < 1000; j++)
        {
          true_rand(&a, bits);

          ssh_mp_square(&b, &a);

          if (ssh_mp_is_perfect_square(&b) == 0)
            {
              printf("error: square/perfect square failed.\n");
              print_int("a = ", &a);
              print_int("a^2 = ", &b);
              ssh_mp_sqrt(&c, &b);
              print_int("a' = ", &c);
              exit(1);
            }
        }
    }

  if (flag)
    {
      printf(" * gcd/gcdext tests\n");
      for (j = 0; j < 1000; j++)
        {
          true_rand(&a, bits);
          true_rand(&b, bits);
          
          if (ssh_mp_cmp_ui(&a, 0) == 0 ||
              ssh_mp_cmp_ui(&b, 0) == 0)
            continue;
      
          ssh_mp_abs(&a, &a);
          ssh_mp_abs(&b, &b);
      
          ssh_mp_gcd(&c, &a, &b);
          if (ssh_mp_cmp_ui(&c, 1) == 0)
            {
              ssh_mp_gcdext(&d, &e, &f, &a, &b);
              
              if (ssh_mp_cmp(&d, &c) != 0)
                {
                  printf("error: gcd/gcdext failed.\n");
                  exit(1);
                }
              
              ssh_mp_mul(&e, &a, &e);
              ssh_mp_mul(&f, &b, &f);
              ssh_mp_add(&f, &f, &e);
              if (ssh_mp_cmp(&f, &d) != 0)
                {
                  printf("error: gcdext failed.\n");
                  exit(1);
                }
            }
        }
    }

  printf(" * conversion testing.\n");
  for (i = 0; i < 1000; i++)
    {
      char *str;
      int base;

      do
        {
          base = random() % 65;
        }
      while (base < 2);
      
      true_rand(&a, bits);

      str = ssh_mp_get_str(NULL, base, &a);
      ssh_mp_set_str(&b, str, base);

      if (ssh_mp_cmp(&a, &b) != 0)
        {
          printf("error: conversion to integer failed in base %d.\n", base);
          print_int("a = ", &a);
          ssh_mp_dump(&a);
          print_int("b = ", &b);
          ssh_mp_dump(&b);
          printf("Output: %s\n", str);
          ssh_xfree(str);
          exit(1);
        }

      ssh_xfree(str);

      /* Test for automatic recognition. */
      
      switch (random() % 3)
        {
        case 0:
          base = 8;
          break;
        case 1:
          base = 10;
          break;
        case 2:
          base = 16;
          break;
        }
      
      str = ssh_mp_get_str(NULL, base, &a);
      ssh_mp_set_str(&b, str, 0);

      if (ssh_mp_cmp(&a, &b) != 0)
        {
          printf("error: automatic recognition of base %d.\n", base);
          print_int("a = ", &a);
          ssh_mp_dump(&a);
          print_int("b = ", &b);
          ssh_mp_dump(&b);
          printf("Output: %s\n", str);
          ssh_xfree(str);
          exit(1);
        }
      ssh_xfree(str);
      
    }
  
  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&d);
  ssh_mp_clear(&e);
  ssh_mp_clear(&f);
}

void test_mod(int flag, int bits)
{
  /* Montgomery testing. */
  SshIntModQ a0, b0, c0;
  SshInt  a1, b1, c1, m1, d;
  SshIntModuli m0;
  int i;
  Boolean rv1, rv2;

  ssh_mp_init(&a1);
  ssh_mp_init(&b1);
  ssh_mp_init(&c1);
  ssh_mp_init(&m1);
  ssh_mp_init(&d);

  printf(" * random moduli search\n");

  do
    {
      ssh_mp_rand(&m1, bits);
      while (ssh_mp_next_prime(&m1, &m1) == FALSE)
        ssh_mp_rand(&m1, bits);
    }
  while (ssh_mpm_init_m(&m0, &m1) == FALSE);

  ssh_mpm_init(&a0, &m0);
  ssh_mpm_init(&b0, &m0);
  ssh_mpm_init(&c0, &m0);

  print_int ("m1 = ", &m1);

  /* Additions. */
  printf(" * addition test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_add(&c0, &a0, &b0);

      ssh_mp_add(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 + b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 + b0 = ", &c0);
          exit(1);
        }
    }
  
  /* Subtractions. */
  printf(" * subtraction test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_sub(&c0, &a0, &b0);

      ssh_mp_sub(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 - b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 - b0 = ", &c0);
          exit(1);
        }
    }

  /* Multiplications. */
  printf(" * multiplication test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_mul(&c0, &a0, &b0);

      ssh_mp_mul(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1      = ", &a1);
          print_int ("  b1      = ", &b1);
          print_int ("  a1 * b1 = ", &c1);
          print_mont("  a0      = ", &a0);
          print_mont("  b0      = ", &b0);
          print_mont("  a0 * b0 = ", &c0);
          ssh_mpm_dump(&c0);
          exit(1);
        }
    }

  /* Squarings. */
  printf(" * squaring test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_square(&c0, &a0);

      ssh_mp_square(&c1, &a1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1   = ", &a1);
          print_int ("  a1^2 = ", &c1);
          print_mont("  a0   = ", &a0);
          print_mont("  a0^2 = ", &c0);
          exit(1);
        }
    }

  printf(" * inversion test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      rv1 = ssh_mpm_invert(&c0, &a0);
      rv2 = ssh_mp_invert(&c1, &a1, &m1);

      if (rv1 == FALSE && rv2 == FALSE)
        continue;

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1    = ", &a1);
          print_int ("  a1^-1 = ", &c1);
          print_mont("  a0    = ", &a0);
          print_mont("  a0^-1 = ", &c0);
          exit(1);
        }
    }

  printf(" * mul ui test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_mul_ui(&c0, &a0, i + 1);

      ssh_mp_mul_ui(&c1, &a1, i + 1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1     = ", &a1);
          print_int ("  a1 * u = ", &c1);
          print_mont("  a0     = ", &a0);
          print_mont("  a0 * u = ", &c0);
          exit(1);
        }
    }

  printf(" * mul 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_mul_2exp(&c0, &a0, (i % 50) + 1);

      ssh_mp_mul_2exp(&c1, &a1, (i % 50) + 1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1       = ", &a1);
          print_int ("  a1 * 2^u = ", &c1);
          print_mont("  a0       = ", &a0);
          print_mont("  a0 * 2^u = ", &c0);
          exit(1);
        }
    }

  printf(" * div 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_div_2exp(&c0, &a0, (i % 5));

      ssh_mp_set_ui(&d, 1 << (i % 5));
      ssh_mp_invert(&d, &d, &m1);
      ssh_mp_mul(&c1, &a1, &d);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        {
          printf("error: mismatch at iteration %u\n", i);
          print_int ("  a1     = ", &a1);
          print_int ("  a1 * u = ", &c1);
          print_mont("  a0     = ", &a0);
          print_mont("  a0 * u = ", &c0);
          exit(1);
        }
    }


  
  ssh_mpm_clear(&a0);
  ssh_mpm_clear(&b0);
  ssh_mpm_clear(&c0);
  ssh_mpm_clear_m(&m0);

  ssh_mp_clear(&a1);
  ssh_mp_clear(&b1);
  ssh_mp_clear(&c1);
  ssh_mp_clear(&m1);
  ssh_mp_clear(&d);
}





/* Speed tests of some sort. */

void timing_int(int bits)
{
  SshInt a, b, c, d, e, f[100];
  TimeIt tmit;
  unsigned int i, j;
  SshMpPowmBase base;

  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&d);
  ssh_mp_init(&e);
  
  printf("Timing integer arithmetic.\n");

  printf("Bits = %u\n", bits);

  for (i = 0; i < 100; i++)
    {
      ssh_mp_init(&f[i]);
      ssh_mp_rand(&f[i], bits);
      if ((ssh_mp_get_ui(&f[i]) & 0x1) == 0)
        ssh_mp_add_ui(&f[i], &f[i], 1);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
         bits, bits, bits + bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits);
      for (j = 0; j < 100; j++)
        ssh_mp_mul(&a, &f[j], &b);
    }
  check_timing(&tmit);

  printf("  * %g multiplications per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));
  
  printf("Timing divisions [%u / %u = %u] \n",
         bits + bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
        ssh_mp_div(&a, &c, &b, &f[j]);
    }
  check_timing(&tmit);

  printf("  * %g divisions per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));

  
  printf("Timing modular reductions [%u %% %u = %u] \n",
         bits + bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
        ssh_mp_mod(&a, &b, &f[j]);
    }
  check_timing(&tmit);

  printf("  * %g modular reductions per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));

  
  printf("Timing squarings [%u^2 = %u] \n",
         bits, bits + bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits);
      for (j = 0; j < 100; j++)
        ssh_mp_square(&a, &b);
    }
  check_timing(&tmit);

  printf("  * %g squarings per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));

  printf("Timing modexp [%u^%u %% %u = %u] \n",
         bits, bits, bits, bits);
  start_timing(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mp_rand(&b, bits);
      ssh_mp_powm(&a, &b, &f[j + 1], &f[j + 2]);
    }
  check_timing(&tmit);

  printf("  * %g modexps per sec (%g cycles)\n",
         ((double)10)/(tmit.real_secs), (double)tmit.cycles/(10.0));


  /* Generate the fixed base. */
  do
    {
      ssh_mp_rand(&b, bits);
    }
  while (ssh_mp_get_size(&b, 2) < bits-1);

  /* Create the base. */
  ssh_mp_powm_with_base_init(&b, &f[2], &base);

  if (base.defined == FALSE)
    ssh_fatal("error: could not define base.");
    
  printf("Timing modexp with fixed base [%u^%u %% %u = %u] \n",
         bits, bits, bits, bits);

  start_timing(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    ssh_mp_powm_with_base(&a, &f[j + 1], &base);
  check_timing(&tmit);

  printf("  * %g modexps per sec (%g cycles)\n",
         ((double)10)/(tmit.real_secs), (double)tmit.cycles/(10.0));

  ssh_mp_powm_with_base_clear(&base);
  
  
#define ENTROPY_BITS 256
  
  printf("Timing modexp [%u^%u %% %u = %u] \n",
         bits, ENTROPY_BITS, bits, bits);
  start_timing(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mp_rand(&b, ENTROPY_BITS);
      ssh_mp_set_bit(&b, ENTROPY_BITS);
      ssh_mp_powm(&a, &f[j+1], &b, &f[j + 2]);
    }
  check_timing(&tmit);

  printf("  * %g modexps per sec (%g cycles)\n",
         ((double)10)/(tmit.real_secs), (double)tmit.cycles/(10.0));

  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&d);
  ssh_mp_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mp_clear(&f[i]);
}

void timing_modular(int bits)
{
  SshIntModQ b, c, d, e, f[100];
  SshIntModuli m;
  SshInt a;
  int i, j;
  TimeIt tmit;
  
  ssh_mp_init(&a);

  do
    {
      ssh_mp_rand(&a, bits);
      while (ssh_mp_next_prime(&a, &a) == FALSE)
        ssh_mp_rand(&a, bits);
    }
  while (ssh_mp_get_size(&a, 2) < bits - 1);

  printf("Timing modular arithmetic.\n");
  if (ssh_mpm_init_m(&m, &a) == FALSE)
    ssh_fatal("timing_modular: could not initialize modular arithmetic.");

  printf("Bits = %u\n", bits);

  ssh_mpm_init(&b, &m);
  ssh_mpm_init(&c, &m);
  ssh_mpm_init(&d, &m);
  ssh_mpm_init(&e, &m);
  
  for (i = 0; i < 100; i++)
    {
      ssh_mpm_init(&f[i], &m);
      ssh_mp_rand(&a, bits);
      ssh_mpm_set_mp(&f[i], &a);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
         bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mpm_set(&b, &f[i]);
      for (j = 0; j < 100; j++)
        ssh_mpm_mul(&c, &f[j], &b);
    }
  check_timing(&tmit);

  printf("  * %g multiplications per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));
  
  printf("Timing squarings [%u^2 = %u] \n",
         bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    for (j = 0; j < 100; j++)
      ssh_mpm_square(&b, &f[j]);
  check_timing(&tmit);

  printf("  * %g squarings per sec (%g cycles)\n",
         ((double)50*100)/(tmit.real_secs), (double)tmit.cycles/(50*100.0));

  ssh_mpm_clear(&b);
  ssh_mpm_clear(&c);
  ssh_mpm_clear(&d);
  ssh_mpm_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mpm_clear(&f[i]);
  ssh_mpm_clear_m(&m);
  ssh_mp_clear(&a);  
}

/* Routines for handling the arguments etc. */

typedef struct CommandRec
{
  char *name;
  int  type;
  int  args;
} Command;

#define C_NONE    -1
#define C_HELP    0
#define C_ALL     1
#define C_ITR     2
#define C_GF2N    3
#define C_INT     4
#define C_MOD     5
#define C_BIN     6
#define C_POLY2N  7
#define C_ECP     8
#define C_EC2N    9
#define C_FEC2N   10

#define C_BITS     20
#define C_BITS_ADV 21

#define C_TIMING   30

const Command commands[] =
{
  { "-h", C_HELP, 0 },
  { "--help", C_HELP, 0 },

  { "-a", C_ALL, 0 },
  { "--all", C_ALL, 0 },

  { "-i", C_ITR, 1 },
  { "--iterations", C_ITR, 1 },

  { "-b", C_BITS, 1 },
  { "--bits", C_BITS, 1 },
  { "-ba", C_BITS_ADV, 1 },
  { "--bits-advance", C_BITS_ADV, 1 },

  { "-t", C_TIMING, 0 },
  { "--timing", C_TIMING, 0 },
  
  /* General classes of tests. */
  { "--integer", C_INT, 1 },
  { "--modular", C_MOD, 1 },
  
  
  { NULL }
};

int check_arg(char *str, int *args)
{
  int i;

  for (i = 0; commands[i].name; i++)
    if (strcmp(str, commands[i].name) == 0)
      {
        *args = commands[i].args;
        return commands[i].type;
      }
  
  *args = 0;
  return C_NONE;
}

void usage(void)
{
  printf("usage: t-mathtest [options]\n"
         "options:\n"
         " -a     run all tests (might take longer)\n"
         " -t     run also timings for modules\n"
         " -i xx  run all tests xx times (will use different random seeds)\n"
         " -h     this help.\n"
         " -b     initial bits of the test parameters.\n"
         "advanced options: \n"
         " --integer [on|off] sets the integer arithmetic testing on/off.\n"
         " --modular [on|off] sets the (mod p) arithmetic testing on/off.\n"
         );
  exit(1);
}

int on_off(char *str)
{
  if (strcmp(str, "on") == 0)
    return 1;
  if (strcmp(str, "off") == 0)
    return 0;

  printf("error: '%s' should be 'on' or 'off'.\n", str);
  exit(1);
}

int main(int ac, char *av[])
{
  int i, all, itr, type, args;
  int gf2n, mod, integer, ecp, ec2n, fec2n, poly2n, bpoly,
    bits, bits_advance, timing;
  
  printf("Arithmetic library test suite\n"
         "Copyright (C) 1998 SSH Communications Security, Ltd.\n"
         "              All rights reserved.\n"
         "\n"
         "Features: \n"
         "  - integer arithmetic\n"
         "  - finite field arithmetic (mod p)\n"
         "\n");
  
  /* Randomize the random number generator. */
  srandom(ssh_time());

  /* Don't use this if you want to test the mathlibrary :) */
  /*extra_test(); */
  /*test_rsa_kphi(); */
  
  all = 0;
  itr = 1;

  timing = 0;
  
  bits = 512;
  bits_advance = 128;
  
  gf2n     = 0;
  integer  = 1;
  mod      = 0;
  bpoly    = 0;
  ecp      = 0;
  ec2n     = 0;
  fec2n    = 0;
  poly2n   = 0;
  
  for (i = 1; i < ac; i++)
    {
      type = check_arg(av[i], &args);
      if (args >= ac - i)
        {
          printf("error: not enough arguments for '%s'.\n",
                 av[i]);
          exit(1);
        }

      switch (type)
        {
        case C_INT:
          integer = on_off(av[i + 1]);
          i++;
          break;
        case C_MOD:
          mod = on_off(av[i + 1]);
          i++;
          break;
          
        case C_BITS:
          bits = atoi(av[i + 1]);
          i++;
          break;
        case C_BITS_ADV:
          bits_advance = atoi(av[i + 1]);
          i++;
          break;
          
        case C_HELP:
          usage();
          break;
        case C_ALL:
          all = 1;
          break;
        case C_TIMING:
          timing = 1;
          break;
        case C_ITR:
          itr = atoi(av[i + 1]);
          i++;
          break;
        case C_NONE:
          printf("error: '%s' not a valid option.\n",
                 av[i]);
          usage();
          break;
        }
    }

  if (itr <= 0)
    itr = 1;

  if (bits < 10)
    bits = 10;

  for (i = 0; i < itr; i++, bits += bits_advance)
    {
      if (bits < 10)
        bits = 512;
      
      if (integer)
        {
          test_int(all, bits);
          if (timing)
            timing_int(bits);
        }
      if (mod)     
        {
          test_mod(all, bits);
          if (timing)
            timing_modular(bits);
        }
    }

  return 0;
}
