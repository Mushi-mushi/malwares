/*

  testfile.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Jul 23 22:36:43 1997 [mkojo]

  Testing some things with GMP etc. 

  */

/*
 * $Id: t-sophie-germain.c,v 1.4 1999/04/29 13:38:31 huima Exp $
 * $Log: t-sophie-germain.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sieve.h"

/* Idea here is to find:

   p = c*2 + 1

   Thus we can see that

   p (mod k) = c*2 (mod k) + 1 (mod k)

             = c (mod k) * 2 (mod k) + 1 (mod k)

   However, we want

     p = n + s

   thus we have to select

     p = n + sk = c*2 + 1 + sk

   if at start s = 0 then 
             
     c = (n - 1)/2

   if s > 0 then

     n + sk = 2c + 1
     (n + sk - 1)/2 = c
     (n - 1)/2 + sk/2 = c
     (n - 1)/2 = c - sk/2

     c*2 + 1 + sk = n + sk

     (c + sk/2)*2 + 1

   */
void find_safe_prime(unsigned int sieve_size, SshInt *input, SshInt *add,
                     SshInt *prime)
{
  unsigned long *table, *add_table, *primes;
  unsigned int len, t, p, i, j;
  SshInt v, s, ret, aux;
  SshSieve sieve;
  Boolean rv;

  if ((ssh_mp_get_ui(input) & 0x1) == 0x0)
    ssh_mp_add_ui(input, input, 1);

  ssh_sieve_allocate_ui(&sieve, sieve_size, 1000000);
  for (len = 0, p = 2; p; p = ssh_sieve_next_prime(p, &sieve), len++)
    ;
  len--;
  
  if (len > 500000)
    {
      printf("Too many primes.\n");
      exit(1);
    }
  
  ssh_mp_init(&v);
  ssh_mp_init(&s);
  ssh_mp_init(&ret);
  ssh_mp_init(&aux);
  /* Compute v = (input - 1)/2 */
  ssh_mp_sub_ui(&v, input, 1);
  ssh_mp_div_ui(&v, &v, 2);

  /* Compute add */
  ssh_mp_set(&s, add);
  ssh_mp_div_ui(&s, &s, 2);

  printf("Initializing tables.\n");
  
  table = ssh_xmalloc(len*sizeof(*table));
  add_table = ssh_xmalloc(len*sizeof(*add_table));
  primes = ssh_xmalloc(len * sizeof(*primes));
  for (i = 0, p = 2; i < len ; i++,
         p = ssh_sieve_next_prime(p, &sieve))
    {
      ssh_mp_mod_ui2(&aux, &v, p);
      table[i] = ssh_mp_get_ui(&aux);
      ssh_mp_mod_ui2(&aux, &s, p);
      add_table[i] = ssh_mp_get_ui(&aux);
      primes[i] = p;
    }

  ssh_sieve_free(&sieve);

  printf("Starting to search.\n");
  
  /* We assume that only 16 million choices are needed. */
  for (i = 0; i < (1 << 24); i++)
    {
      if (i > 0 && (i & 0x0f) == 0)
        {
          /* Doing something. */
          printf(".");
          fflush(stdout);
        }
      rv = TRUE;
      for (j = 0; j < len; j++)
        {
          p = primes[j];

          if (table[j] == 0)
            rv = FALSE;
          else
            {
              /* If k < p then (k*2 + 1) < 2p */
              t = table[j] * 2 + 1;
              if (t > p)
                t -= p;
              if (t == 0)
                rv = FALSE;
            }
          
          table[j] += add_table[j];
          if (table[j] >= p)
            table[j] -= p;
        }
      if (rv == FALSE)
        continue; 

      printf("x");
      fflush(stdout);

      /* v = n + s*k*2 <=> c*2 + 1 = v = n + 2sk

         c = (n + 2sk - 1)/2 = (n - 1)/2 + sk
         
         */
      ssh_mp_mul_ui(&s, add, i);
      ssh_mp_add(&v, input, &s);
      ssh_mp_set(&ret, &v);
      
      ssh_mp_powm_ui(&aux, 2, &ret, &ret);
      if (ssh_mp_cmp_ui(&aux, 2) == 0)
        {
          printf("1");
          fflush(stdout);
          ssh_mp_sub_ui(&v, &v, 1);
          ssh_mp_div_ui(&v, &v, 2);

          if (ssh_mp_get_ui(&v) & 1)
            {
              ssh_mp_powm_ui(&aux, 2, &v, &v);
              if (ssh_mp_cmp_ui(&aux, 2) == 0)
                {
                  printf("2");
                  fflush(stdout);
                  if (ssh_mp_is_probable_prime(&ret, 20))
                    {
                      printf("3");
                      fflush(stdout);
                      if (ssh_mp_is_probable_prime(&v, 20))
                        break;
                    }
                }
            }
        }
    }

  ssh_xfree(table);
  ssh_xfree(add_table);
  ssh_xfree(primes);

  printf("\nThe i is: %d\n", i);
  printf("Safe prime: \n");
  ssh_mp_out_str(NULL, 10, &ret);
  ssh_mp_set(prime, &ret);
  printf("\nIt's orders large prime divisor:\n");
  ssh_mp_out_str(NULL, 10, &v);
  printf("\n");

  ssh_mp_clear(&v);
  ssh_mp_clear(&s);
  ssh_mp_clear(&ret);
  ssh_mp_clear(&aux);
}

int main(int ac, char *av[])
{
  SshInt input, add, prime;
  unsigned int sieve_size;

  ssh_mp_init(&input);
  ssh_mp_init(&add);
  ssh_mp_init(&prime);

  if (ac == 1)
    {
      sieve_size = 20000;
      ssh_mp_set_str(&input, "1", 0);
      ssh_mp_set_str(&add, "2", 0);
    }
  else if (ac < 4)
    {
      printf("Program for finding Sophie Germain primes.\n");
      printf("usage: gmpt sieve-size start add\n");
      exit(1);
    }
  else
    {
      sieve_size = atoi(av[1]);
      ssh_mp_set_str(&input, av[2], 0);
      ssh_mp_set_str(&add, av[3], 0);
    }
  
  find_safe_prime(sieve_size, &input, &add, &prime);

  if (ac == 1)
    {
      if (ssh_mp_cmp_ui(&prime, 39983) == 0)
        printf("OK\n");
      else
        printf("Find_safe_prime returned wrong number, it should have returned 39983\n");
    }
  ssh_mp_clear(&prime);
  ssh_mp_clear(&input);
  ssh_mp_clear(&add);
  exit(0);
}
