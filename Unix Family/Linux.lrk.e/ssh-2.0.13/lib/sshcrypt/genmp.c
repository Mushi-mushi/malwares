/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon May  6 00:18:19 1996 [huima]

  This file contains generic functions which have to do with
  multiple-precision integers but are not provided by the GMP library.

  TODO:

    remove almost everything from this file and move them to
    sshmath/sshmp.c or equivalent in that directory.

    What stays here?

    Mainly routines that handle random numbers, e.g. use the
    cryptographically strong random number generator. We don't want to
    move it into sshmath, it wouldn't do much there.
  
  */

/*
 * $Id: genmp.c,v 1.29 1999/04/29 13:38:05 huima Exp $
 * $Log: genmp.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshcrypt.h"
#include "libmonitor.h"
#include "genmp.h"
#include "sshgetput.h"

/* This prime table is used in assumption that generating prime table
   at runtime is slow, which it isn't. Might become obsolete some day. */

const unsigned int ssh_prime_table[SSH_MAX_PRIMES_IN_TABLE + 1] =
{ 
  2, 3, 5, 7, 11, 13, 17, 19,
  23, 29, 31, 37, 41, 43, 47, 53,
  59, 61, 67, 71, 73, 79, 83, 89,
  97, 101, 103, 107, 109, 113, 127, 131,
  137, 139, 149, 151, 157, 163, 167, 173,
  179, 181, 191, 193, 197, 199, 211, 223,
  227, 229, 233, 239, 241, 251, 257, 263,
  269, 271, 277, 281, 283, 293, 307, 311,
  313, 317, 331, 337, 347, 349, 353, 359,
  367, 373, 379, 383, 389, 397, 401, 409,
  419, 421, 431, 433, 439, 443, 449, 457,
  461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569,
  571, 577, 587, 593, 599, 601, 607, 613,
  617, 619, 631, 641, 643, 647, 653, 659,
  661, 673, 677, 683, 691, 701, 709, 719,
  727, 733, 739, 743, 751, 757, 761, 769,
  773, 787, 797, 809, 811, 821, 823, 827,
  829, 839, 853, 857, 859, 863, 877, 881,
  883, 887, 907, 911, 919, 929, 937, 941,
  947, 953, 967, 971, 977, 983, 991, 997,
  1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
  1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
  1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
  1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
  1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
  1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
  1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
  1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459,
  1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
  1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
  1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
  1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
  1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747,
  1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
  1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
  1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949,
  1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
  2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
  2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
  2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203,
  2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
  2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311,
  2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377,
  2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
  2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503,
  2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
  2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
  2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
  2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
  2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
  2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861,
  2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939,
  2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
  3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
  3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
  3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
  3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301,
  3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347,
  3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
  3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
  3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
  3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
  3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671,
  3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
  3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
  3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863,
  3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923,
  3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003,
  4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,
  4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129,
  4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211,
  4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259,
  4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337,
  4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
  4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481,
  4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547,
  4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621,
  4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673,
  4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
  4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813,
  4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909,
  4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967,
  4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011,
  5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
  5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167,
  5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233,
  5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309,
  5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399,
  5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
  5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507,
  5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573,
  5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653,
  5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711,
  5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
  5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849,
  5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897,
  5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007,
  6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073,
  6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
  6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211,
  6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271,
  6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329,
  6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379,
  6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
  6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563,
  6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637,
  6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701,
  6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779,
  6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
  6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907,
  6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971,
  6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027,
  7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121,
  7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
  7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253,
  7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349,
  7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457,
  7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517,
  7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
  7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621,
  7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691,
  7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757,
  7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853,
  7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
  7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009,
  8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087,
  8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161,
  8167, 8171, 8179, 8191,
  0};

/* Generate a random integer (using the cryptographically strong random number
   generator). */

void ssh_mp_random_integer(SshInt *ret, SshRandomState state,
                           unsigned int bits)
{
  unsigned int i;
  SshUInt32 limb;
  
  ssh_mp_set_ui(ret, 0);
  /* Loop 32 bit limbs */
  for (i = 0; i < bits; i += 32)
    {
      /* Construct one limb */
      limb = (((SshUInt32)ssh_random_get_byte(state) << 24) |
              ((SshUInt32)ssh_random_get_byte(state) << 16) |
              ((SshUInt32)ssh_random_get_byte(state) << 8) |
              ((SshUInt32)ssh_random_get_byte(state) & 0xff));
      /* Shift and add */
      ssh_mp_mul_2exp(ret, ret, 32);
      ssh_mp_add_ui(ret, ret, limb);
    }
  /* Cut unneeded bits off */
  ssh_mp_mod_2exp(ret, ret, bits);
}

/* Generate traditional prime. */

void ssh_mp_random_prime(SshInt *ret, SshRandomState state,
                         unsigned int bits)
{
  SshInt start, aux;
  unsigned int num_primes;
  long *moduli;
  long difference;

  /* Progress monitoring. */
  unsigned int progress_counter = 0;

  /* Initialize the prime search. */
  ssh_mp_init(&start);
  ssh_mp_init(&aux);

 retry:

  /* Pick a random integer of the appropriate size. */
  ssh_mp_random_integer(&start, state, bits);

  /* Set the highest bit. */
  ssh_mp_set_ui(&aux, 1);
  ssh_mp_mul_2exp(&aux, &aux, bits - 1);
  ssh_mp_or(&start, &start, &aux);
  /* Set the lowest bit to make it odd. */
  ssh_mp_set_ui(&aux, 1);
  ssh_mp_or(&start, &start, &aux);

  /* Initialize moduli of the small primes with respect to the given
     random number. */
  moduli = ssh_xmalloc(SSH_MAX_PRIMES_IN_TABLE * sizeof(moduli[0]));
  if (bits < 16)
    num_primes = 0; /* Don\'t use the table for very small numbers. */
  else
    {
      for (num_primes = 1; ssh_prime_table[num_primes] != 0; num_primes++)
        {
          ssh_mp_mod_ui2(&aux, &start, ssh_prime_table[num_primes]);
          moduli[num_primes] = ssh_mp_get_ui(&aux);
        }
    }

  /* Look for numbers that are not evenly divisible by any of the small
     primes. */
  for (difference = 0; ; difference += 2)
    {
      unsigned int i;
      
      if (difference > 0x70000000)
        { /* Should never happen, I think... */
          ssh_xfree(moduli);
          goto retry;
        }

      /* Check if it is a multiple of any small prime.  Note that this
         updates the moduli into negative values as difference grows. */
      for (i = 1; i < num_primes; i++)
        {
          while (moduli[i] + difference >= ssh_prime_table[i])
            moduli[i] -= ssh_prime_table[i];
          if (moduli[i] + difference == 0)
            break;
        }
      if (i < num_primes)
        continue; /* Multiple of a known prime. */

      /* Progress information. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);
      
      /* Compute the number in question. */
      ssh_mp_add_ui(ret, &start, difference);

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mp_is_probable_prime(ret, 20))
        break; 
    }

  /* Found a (probable) prime.  It is in ret. */
  /* Free the small prime moduli; they are no longer needed. */
  ssh_xfree(moduli);

  /* Sanity check: does it still have the high bit set (we might have
     wrapped around)? */
  ssh_mp_div_2exp(&aux, ret, bits - 1);
  if (ssh_mp_get_ui(&aux) != 1)
    {
      goto retry;
    }
  ssh_mp_clear(&start);
  ssh_mp_clear(&aux);
  /* Return value already set in ret. */
}

/* Find next prime, given a start value. */
#if 0
void ssh_mp_next_prime(SshInt *ret, SshInt *x)
{
  SshInt aux, start;
  unsigned int num_primes;
  unsigned long *moduli;
  unsigned long difference;
  Boolean divisible;
  unsigned long i, t;

  /* Progress monitoring. */
  unsigned int progress_counter = 0;
  
  ssh_mp_init_set(&start, x);
  
  /* Check for even start values, force odd. */
  if (!(ssh_mp_get_ui(&start) & 0x1))
    {
      ssh_mp_add_ui(&start, &start, 1);
    }
  else
    {
      ssh_mp_add_ui(&start, &start, 2);
    }

  /* Precheck for very small start values. */
  if (ssh_mp_cmp_ui(&start, ssh_prime_table[SSH_MAX_PRIMES_IN_TABLE - 2]) <= 0)
    {
      if (ssh_mp_cmp_ui(&start, 2) < 0)
        {
          /* Give the smallest (it could be thought that 1 is not
             prime, but the unit) prime. */
          ssh_mp_set_ui(ret, 2);
          return;
        }

      /* We got rather small value seek for it. */
      t = ssh_mp_get_ui(&start);

      /* Check using the prime table, which we already know. */
      for (num_primes = 1; ssh_prime_table[num_primes] != 0; num_primes++)
        {
          if (ssh_prime_table[num_primes] < t)
            {
              if (ssh_prime_table[num_primes + 1] != 0)
                {
                  ssh_mp_set_ui(ret, ssh_prime_table[num_primes + 1]);
                  return;
                }
              
              break;
            }
          if (ssh_prime_table[num_primes] == t)
            {
              ssh_mp_set_ui(ret, ssh_prime_table[num_primes]);
              return;
            }
        }
    }
  
  /* Initialize some temporary variables. */
  ssh_mp_init(&aux);
  
  /* Initialize moduli of the small primes with respect to the given
     random number. */
  moduli = ssh_xmalloc(SSH_MAX_PRIMES_IN_TABLE * sizeof(moduli[0]));

  for (num_primes = 1; ssh_prime_table[num_primes] != 0; num_primes++)
    {
      ssh_mp_mod_ui2(&aux, &start, ssh_prime_table[num_primes]);
      moduli[num_primes] = ssh_mp_get_ui(&aux);
    }

  /* Look for numbers that are not evenly divisible by any of the small
     primes. */
  for (difference = 0; ; difference += 2)
    {
      if (difference > (0xffffffff - 2))
        ssh_fatal("ssh_mp_next_prime: prime was not found.");

      /* Check if it is a multiple of any small prime. Implemented little
         different, this might be a matter of taste... I guess this is
         in average as fast. */
      for (i = 1, divisible = FALSE; i < num_primes; i++)
        {
          if (moduli[i] >= ssh_prime_table[i])
            moduli[i] -= ssh_prime_table[i];
          if (moduli[i] == 0)
            divisible = TRUE;
          moduli[i] += 2;
        }
      if (divisible)
        continue; /* Multiple of a known prime. */

      /* Acknowledge application that we have found possibly good number. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);
      
      /* Compute the number in question. */
      ssh_mp_add_ui(ret, &start, difference);

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mp_is_probable_prime(ret, 15))
        break; 
    }

  /* Free the small prime moduli; they are no longer needed. */
  ssh_xfree(moduli);

  ssh_mp_clear(&aux);
  /* Return value already set in ret. */
}
#endif

/* The P1363 prime generation (from working draft i.e. might change in
   future). */

/* Generate random prime number using explicitly set limits. */

void ssh_mp_random_prime_within_limits(SshInt *ret,
                                       int min_bits, int max_bits,
                                       SshRandomState state)
{
  SshInt pprime, temp;
  unsigned long *moduli, difference, num_primes;
  unsigned int i, len;
  Boolean divisible;

  /* Progress monitoring. */
  unsigned int progress_counter = 0;
  
  /* Verify that limits are in correct order. */
  if (min_bits >= max_bits)
    {
      /* Assume we still want random prime so get it but use more bits
         rather than less. */
      
      min_bits = max_bits;
      max_bits = min_bits + 2;
    }

  ssh_mp_init(&pprime);
  ssh_mp_init(&temp);

retry:
  
  /* Get a random integer within limits. (Should not be too difficult,
     could be done also by setting the highest bit, but that approach was
     taken in the above code so doing this differently). */
  do {
    ssh_mp_random_integer(&pprime, state, max_bits);
    len = ssh_mp_get_size(&pprime, 2);
  } while (len < min_bits);

  /* If even the make it odd. */
  if ((ssh_mp_get_ui(&pprime) & 0x1) == 0)
    ssh_mp_add_ui(&pprime, &pprime, 1);

  /* Initialize moduli of the small primes with respect to the given
     random number. */
  moduli = ssh_xmalloc(SSH_MAX_PRIMES_IN_TABLE * sizeof(*moduli));

  for (num_primes = 1; ssh_prime_table[num_primes] != 0; num_primes++)
    {
      ssh_mp_mod_ui2(&temp, &pprime, ssh_prime_table[num_primes]);
      moduli[num_primes] = ssh_mp_get_ui(&temp);
    }

  /* Look for numbers that are not evenly divisible by any of the small
     primes. */
  difference = 0;
  
  while (1)
    {
      /* Set the divisible flag. */
      divisible = FALSE;

      /* In now and them add the difference to the probable prime. */
      if (difference > 1000)
        {
          ssh_mp_add_ui(&pprime, &pprime, difference);
          difference = 0;

          len = ssh_mp_get_size(&pprime, 2);
          if (len > max_bits)
            {
              ssh_mp_set_ui(&temp, 1);
              ssh_mp_mul_2exp(&temp, &temp, max_bits);
              ssh_mp_sub(&pprime, &pprime, &temp);
              
              ssh_mp_div_2exp(&temp, &temp, max_bits - min_bits);
              ssh_mp_add(&pprime, &pprime, &temp);
              ssh_mp_sub_ui(&pprime, &pprime, 1);

              /* Check that the probable prime is odd. */
              if ((ssh_mp_get_ui(&pprime) & 0x1) == 0)
                ssh_mp_add_ui(&pprime, &pprime, 1);

              /* Compute again the moduli table. */
              for (i = 1; i < num_primes; i++)
                {
                  ssh_mp_mod_ui2(&temp, &pprime, ssh_prime_table[i]);
                  moduli[i] = ssh_mp_get_ui(&temp);
                }
            }
        }
              
      /* Check if it is a multiple of any small prime. */
      for (i = 1; i < num_primes; i++)
        {
          /* Check for this round. */
          if (moduli[i] == 0)
            divisible = TRUE;
          /* Compute for the next round. */
          moduli[i] += 2;
          if (moduli[i] >= ssh_prime_table[i])
            moduli[i] -= ssh_prime_table[i];
        }

      /* Add the difference by 2. */
      difference += 2;
      
      /* Multiple of known prime. */
      if (divisible)
        continue; 

      /* Acknowledge application. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);
      
      /* Set to ret and check if gone over the max limit. */
      ssh_mp_add_ui(&pprime, &pprime, difference);
      difference = 0;

      /* Check the length. */
      len = ssh_mp_get_size(&pprime, 2);
      if (len > max_bits)
        {
          /* compute: pprime - 2^max_bits + 2^min_bits - 1 */
          ssh_mp_set_ui(&temp, 1);
          ssh_mp_mul_2exp(&temp, &temp, max_bits);
          ssh_mp_sub(&pprime, &pprime, &temp);
          ssh_mp_set_ui(&temp, 1);
          ssh_mp_mul_2exp(&temp, &temp, min_bits);
          ssh_mp_add(&pprime, &pprime, &temp);
          ssh_mp_sub_ui(&pprime, &pprime, 1);
          
          /* Check that the probable prime is odd. */
          if ((ssh_mp_get_ui(&pprime) & 0x1) == 0)
            ssh_mp_add_ui(&pprime, &pprime, 1);
          
          /* Compute again the moduli table. */
          for (i = 1; i < num_primes; i++)
            {
              ssh_mp_mod_ui2(&temp, &pprime, ssh_prime_table[i]);
              moduli[i] = ssh_mp_get_ui(&temp);
            }
          continue;
        }
      
      /* Compute the number in question. */
      ssh_mp_set(ret, &pprime);

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mp_is_probable_prime(ret, 15))
        break; 
    }

  /* Found a (probable) prime.  It is in ret. */
  /* Free the small prime moduli; they are no longer needed. */
  ssh_xfree(moduli);

  /* Sanity check. */
  len = ssh_mp_get_size(ret, 2);
  if (len < min_bits || len > max_bits)
    {
      goto retry;
    }
  ssh_mp_clear(&pprime);
  ssh_mp_clear(&temp);
  /* Return value already set in ret. */  
}

/* Generate random prime number using explicitly set limits and
   a congruence condition. ret = a (mod r). This operation is
   rather slow. */

void ssh_mp_random_prime_with_congruence(SshInt *ret,
                                         int min_bits, int max_bits,
                                         SshInt *r, SshInt *a,
                                         SshRandomState state)
{
  SshInt pprime, temp, w, r2;
  unsigned int len;

  unsigned int progress_counter = 0;
  
  /* Verify that limits are in correct order. */
  if (min_bits >= max_bits)
    {
      /* Assume we still want random prime so get it but use more bits
         rather than less. */
      
      min_bits = max_bits;
      max_bits = min_bits + 2;
    }

  ssh_mp_init(&pprime);
  ssh_mp_init(&temp);
  ssh_mp_init(&w);
  ssh_mp_init(&r2);
  
retry:
  
  /* Get a random integer within limits. (Should not be too difficult,
     could be done also by setting the highest bit, but that approach was
     taken in the above code so doing this differently). */
  do {
    ssh_mp_random_integer(&pprime, state, max_bits);
    len = ssh_mp_get_size(&pprime, 2);
  } while (len < min_bits);

  ssh_mp_mul_ui(&r2, r, 2);
  ssh_mp_mod(&w, &pprime, &r2);

  ssh_mp_add(&pprime, &pprime, &r2);
  ssh_mp_add(&pprime, &pprime, a);
  ssh_mp_sub(&pprime, &pprime, &w);
  
  /* If even the make it odd. */
  if ((ssh_mp_get_ui(&pprime) & 0x1) == 0)
    ssh_mp_add(&pprime, &pprime, r);

  while (1)
    {
      ssh_mp_add(&pprime, &pprime, &r2);
      
      /* Check the length. */
      len = ssh_mp_get_size(&pprime, 2);
      if (len > max_bits)
        {
          /* compute: pprime - 2^max_bits + 2^min_bits - 1 */
          ssh_mp_set_ui(&temp, 1);
          ssh_mp_mul_2exp(&temp, &temp, max_bits);
          ssh_mp_sub(&pprime, &pprime, &temp);
          ssh_mp_set_ui(&temp, 1);
          ssh_mp_mul_2exp(&temp, &temp, min_bits);
          ssh_mp_add(&pprime, &pprime, &temp);
          ssh_mp_sub_ui(&pprime, &pprime, 1);
          
          /* Check that the probable prime is odd. */
          if ((ssh_mp_get_ui(&pprime) & 0x1) == 0)
            ssh_mp_add_ui(&pprime, &pprime, 1);

          ssh_mp_mod(&w, &pprime, &r2);
          
          ssh_mp_add(&pprime, &pprime, &r2);
          ssh_mp_add(&pprime, &pprime, a);
          ssh_mp_sub(&pprime, &pprime, &w);
          continue;
        }

      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);
      
      /* Check for primality. */
      
      /* Compute the number in question. */
      ssh_mp_set(ret, &pprime);

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mp_is_probable_prime(ret, 15))
        break;
    }

  /* Sanity check. */
  len = ssh_mp_get_size(ret, 2);
  if (len < min_bits || len > max_bits)
    {
      goto retry;
    }
  ssh_mp_clear(&pprime);
  ssh_mp_clear(&temp);
  ssh_mp_clear(&w);
  ssh_mp_clear(&r2);
  /* Return value already set in ret. */  
}

/* Generate strong random primes P1363 style. Where prime 'prime' satisfies
   prime = 1 (mod r), prime = -1 (mod s), r = 1 (mod t) and r, s, t are all
   large primes. Also 'div' = r. */

void ssh_mp_strong_p1363_random_prime(SshInt *prime, SshInt *div, 
                                      int big_bits, int small_bits,
                                      SshRandomState state)
{
  SshInt t, r, s, u, v, a, temp;
  unsigned int lt_bits, lr_bits, ls_bits;

  if (small_bits < 160 || big_bits < 320)
    ssh_fatal("error: discrete log might be too easy with primes (%d, %d).\n",
              big_bits, small_bits);

  if (small_bits > big_bits)
    big_bits = small_bits + 10;
  
  /* Assume that small_bits > 160. */
  lr_bits = small_bits;
  lt_bits = lr_bits - 10;
  ls_bits = small_bits;
  
  /* Initialize integers. */
  ssh_mp_init(&t);
  ssh_mp_init(&r);
  ssh_mp_init(&s);
  ssh_mp_init(&u);
  ssh_mp_init(&v);
  ssh_mp_init(&a);
  ssh_mp_init(&temp);

  ssh_mp_set_ui(&temp, 1);
  
  ssh_mp_random_prime_within_limits(&t, lt_bits - 1, lt_bits, state);
  ssh_mp_random_prime_with_congruence(&r, lr_bits - 1, lr_bits, &t, &temp,
                                      state);
  ssh_mp_random_prime_within_limits(&s, ls_bits - 1, ls_bits, state);

  /* Invert s (mod r) and r (mod s). */
  ssh_mp_mod_invert(&u, &s, &r);
  ssh_mp_mod_invert(&v, &r, &s);

  /* Compute a = su - rv (mod rs) */
  ssh_mp_mul(&a, &s, &u);
  ssh_mp_mul(&temp, &r, &v);
  ssh_mp_sub(&a, &a, &temp);

  ssh_mp_mul(&temp, &r, &s);
  ssh_mp_mod(&a, &a, &temp);

  ssh_mp_random_prime_with_congruence(prime, big_bits - 1, big_bits, &temp, &a,
                                      state);

  ssh_mp_set(div, &r);
  
  /* Free integers. */
  ssh_mp_clear(&t);
  ssh_mp_clear(&r);
  ssh_mp_clear(&s);
  ssh_mp_clear(&u);
  ssh_mp_clear(&v);
  ssh_mp_clear(&a);
  ssh_mp_clear(&temp);
}

/* Generate a strong random prime. That is, p = q * c + 1, where p and q are
   prime and c > 1.

   Here we use the idea that given random 2^n-1 < x < 2^n, we can compute
   y = x (mod 2q), and then p = x - y + 1 + 2tq. Given this method the
   probability that we get values that are not in the correct range is
   reasonably small. 
   
   */

void ssh_mp_random_strong_prime(SshInt *prime,
                                SshInt *order,
                                int prime_bits, int order_bits,
                                SshRandomState state)
{
  SshInt aux, aux2, u;
  unsigned long *table_q, *table_u;
  unsigned long i, j, table_count, upto;
  Boolean flag;

  unsigned int progress_counter = 0;
  
  /* Check for bugs. */
  if (prime_bits < order_bits)
    ssh_fatal("ssh_mp_random_strong_prime: "
              "requested prime less than the group order!");
  
  /* Keep the running in place. */
  if (prime_bits - order_bits - 1 > 24)
    upto = 1 << 24;
  else
    upto = 1 << (prime_bits - order_bits - 1);
  
  ssh_mp_init(&aux);
  ssh_mp_init(&aux2);
  ssh_mp_init(&u);

  /* There seems to be no real reason to generate this as a strong prime. */
  ssh_mp_random_prime(order, state, order_bits);

  /* Reduce group order. Remember the factor 2. */
  table_q = ssh_xmalloc(SSH_MAX_PRIMES_IN_TABLE * sizeof(table_q[0]) * 2);
  table_u = table_q + SSH_MAX_PRIMES_IN_TABLE;
  for (table_count = 1; ssh_prime_table[table_count] != 0; table_count++)
    {
      ssh_mp_mod_ui2(&aux, order, ssh_prime_table[table_count]);
      table_q[table_count] =
        (ssh_mp_get_ui(&aux) * 2) % ssh_prime_table[table_count];
    }

  /* In case we don't find one quickly enough. */
retry:

  /* Generate a random integer large enough. */
  ssh_mp_random_integer(&u, state, prime_bits);

  /* Set the highest bit on. */
  ssh_mp_set_ui(&aux, 1);
  ssh_mp_mul_2exp(&aux, &aux, prime_bits - 1);
  ssh_mp_or(&u, &u, &aux);
  
  /* Compute the initial value for the prime. */
  ssh_mp_set(&aux, order);
  ssh_mp_mul_2exp(&aux, &aux, 1);
  ssh_mp_mod(&aux2, &u, &aux);
  ssh_mp_sub(&u, &u, &aux2);
  ssh_mp_add_ui(&u, &u, 1);

  /* Now check whether the value is still large enough. */
  if (ssh_mp_get_size(&u, 2) <= prime_bits - 1)
    goto retry;

  /* Now compute the residues of the 'probable prime'. */
  for (j = 1; j < table_count; j++)
    {
      ssh_mp_mod_ui2(&aux, &u, ssh_prime_table[j]);
      table_u[j] = ssh_mp_get_ui(&aux);
    }

  /* Set the 2*q for  later. */
  ssh_mp_mul_2exp(&aux2, order, 1);
  
  /* Loop through until a prime is found. */
  for (i = 0; i < upto; i++)
    {
      flag = TRUE;
      for (j = 1; j < table_count; j++)
        {
          unsigned long cur_p = ssh_prime_table[j];
          unsigned long value = table_u[j];
          /* Check if the result seems to indicate divisible value. */
          if (value >= cur_p)
            value -= cur_p;
          if (value == 0)
            flag = FALSE;
          /* For the next round compute. */
          table_u[j] = value + table_q[j];
        }

      if (flag != TRUE)
        continue;

      /* Acknowledge application that again one possibly good value was
         found. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);
      
      /* Compute the proposed prime. */
      ssh_mp_set(prime, &u);
      ssh_mp_mul_ui(&aux, &aux2, i);
      ssh_mp_add(prime, prime, &aux);

      /* Check that the size of the prime is within range. */
      if (ssh_mp_get_size(prime, 2) > prime_bits)
        goto retry;
      
      /* Miller-Rabin */
      if (ssh_mp_is_probable_prime(prime, 20))
        break;
    }

  if (i >= upto)
    goto retry;

  /* Free the moduli tables. */
  ssh_xfree(table_q);

  /* Free temporary memory. */
  ssh_mp_clear(&aux);
  ssh_mp_clear(&aux2);
  ssh_mp_clear(&u);
}

/* Method for computing a prime that is resistant against p-1 and p+1
   methods of factoring.

   As suggested by John Krueger at sci.crypt (31 Jul 1997).

   The improvement made over Kruegers method is to compute chinese remainder
   theorem so that

     x =  1 mod q1
     x = -1 mod q2
     x =  1 mod 2

   where 1 <= x < q1*q2*2.
     
   Last conqruence, of course, asserts that we don't need to change q1 and
   q2, i.e. there should be number of form  

     t*(q1*q2*2) + x 

   which is prime for some t. Hopefully t need not be too large.
   
   */

void ssh_mp_random_safe_prime(SshInt *p,
                              SshInt *q1,
                              SshInt *q2,
                              unsigned int bits,
                              SshRandomState state)
{
  SshInt t1, t2, t3, y1, y2, y3, m1, m2, m3, q3, qq;
  unsigned int *table_v, *table_u;
  unsigned int table_count, i, j;
  unsigned int upto = (1 << 30);
  Boolean flag;

  unsigned int progress_counter = 0;
  
  /* Initialize a few temporary variables. */
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);
  ssh_mp_init(&t3);
  ssh_mp_init(&m1);
  ssh_mp_init(&m2);
  ssh_mp_init(&m3);
  ssh_mp_init(&y1);
  ssh_mp_init(&y2);
  ssh_mp_init(&y3);
  ssh_mp_init(&qq);
  ssh_mp_init(&q3);
  
  /* Using chinese remainder theorem generate t1 = 1 mod q1, t1 = -1 mod q2.
     Also we'd like to make sure that t1 = 1 mod 2. */

  /* Just in case. */
retry:
  
  /* Generate two large primes. */
  ssh_mp_random_prime(q1, state, (bits/2));
  ssh_mp_random_prime(q2, state, (bits/2));

  /* Compute modulus. */
  ssh_mp_mul(&m3, q1, q2);
  
  /* q3 = 2, thus q1*q2 mod 2 == 1. */
  if ((ssh_mp_get_ui(&m3) & 0x1) == 0)
    ssh_fatal("ssh_mp_random_safe_prime: prime equals to 2.");

  ssh_mp_mul_ui(&qq, &qq, 2);
  
  ssh_mp_mul_ui(&m1, q2, 2);
  ssh_mp_mul_ui(&m2, q1, 2);
  
  ssh_mp_set_ui(&q3, 2);

  /* Compute inverses. */
  ssh_mp_mod_invert(&y1, &m1, q1);
  ssh_mp_mod_invert(&y2, &m2, q2);
  
  /* Compute first part. */
  ssh_mp_mul(&t1, &m1, &y1);

  /* Compute second part. */
  ssh_mp_mul(&t2, &m2, &y2);
  ssh_mp_sub_ui(&t3, q1, 1);
  ssh_mp_mul(&t2, &t2, &t3);
  ssh_mp_mod(&t2, &t2, &qq);

  /* Combine. */
  ssh_mp_add(&t1, &t1, &t2);
  ssh_mp_add(&t1, &t1, &m3);
  ssh_mp_mod(&t1, &t1, &qq);

  /* We never should have to deal with cases like this. */
  if ((ssh_mp_get_ui(&t1) & 0x1) == 0)
    {
      ssh_fatal("ssh_mp_random_safe_prime: should never be divisible by 2!");
      /* Divisible by 2! */
      goto retry;
    }
  
  /* Next search for number of form l + t1 which is a prime where
     l = c*qq.

     We can again use small primes to get rid of values that are not
     prime, and then Fermats little theorem etc. */

  /* Following generate a table where

     v[i] = t1 % p[i],
     u[i] = qq % p[i],

     which can be used for quick checks. */

  /* Allocate tables. */
  table_v = ssh_xmalloc(SSH_MAX_PRIMES_IN_TABLE * sizeof(table_v[0]) * 2);
  table_u = table_v + SSH_MAX_PRIMES_IN_TABLE;

  /* For simplicity we'd like to work only with values > qq. */
  ssh_mp_add(&t1, &t1, &qq);
  
  /* Compute table values. */
  for (table_count = 1; ssh_prime_table[table_count] != 0; table_count++)
    {
      ssh_mp_mod_ui2(&t2, &t1, ssh_prime_table[table_count]);
      table_v[table_count] = ssh_mp_get_ui(&t2);
      ssh_mp_mod_ui2(&t2, &qq, ssh_prime_table[table_count]);
      table_u[table_count] = ssh_mp_get_ui(&t2);
    }

  /* Search for a prime. */
  for (i = 0; i < upto; i++)
    {
      flag = TRUE;
      for (j = 1; j < table_count; j++)
        {
          /* Check if the result seems to indicate divisible value. */
          if (table_v[j] == 0)
            flag = FALSE;
          /* For the next round compute. */
          table_v[j] += table_u[j];
          if (table_v[j] >= ssh_prime_table[j])
            table_v[j] -= ssh_prime_table[j];
        }

      if (flag != TRUE)
        continue;

      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);

      /* Compute the proposed prime. */
      ssh_mp_mul_ui(p, &qq, i);
      ssh_mp_add(p, p, &t1);
      
      /* Miller-Rabin */
      if (ssh_mp_is_probable_prime(p, 20))
        break;
    }

  /* Free tables. */
  ssh_xfree(table_v);

  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
  ssh_mp_clear(&t3);
  ssh_mp_clear(&m1);
  ssh_mp_clear(&m2);
  ssh_mp_clear(&m3);
  ssh_mp_clear(&y1);
  ssh_mp_clear(&y2);
  ssh_mp_clear(&y3);
  ssh_mp_clear(&qq);
  ssh_mp_clear(&q3);
}
                              
/* Basic modular enhancements. Due the nature of extended euclids algorithm
   it sometimes returns integers that are negative. For our cases positive
   results are better. */

int ssh_mp_mod_invert(SshInt *op_dest, const SshInt *op_src,
                      const SshInt *modulo)
{
  int status;

  status = ssh_mp_invert(op_dest, op_src, modulo);

  if (ssh_mp_cmp_ui(op_dest, 0) < 0)
    ssh_mp_add(op_dest, op_dest, modulo);
  
  return status;
}

/* Get random number mod 'modulo' */

/* Random number with some sense in getting only a small number of
   bits. This will avoid most of the extra bits. However, we could
   do it in many other ways too. Like we could distribute the random bits
   in reasonably random fashion around the available size. This would
   ensure that cryptographical use would be slightly safer. */
void ssh_mp_mod_random_entropy(SshInt *op, const SshInt *modulo,
                               SshRandomState state,
                               unsigned int bits)
{
  ssh_mp_random_integer(op, state, bits);
  ssh_mp_mod(op, op, modulo);
}

/* Just plain _modular_ random number generation. */
void ssh_mp_mod_random(SshInt *op, const SshInt *modulo, SshRandomState state)
{
  unsigned int bits;
 
  bits = ssh_mp_bit_size(modulo);
  ssh_mp_random_integer(op, state, bits);
  ssh_mp_mod(op, op, modulo);
}

#if 0

/* Reduced and faster lucas function. Works a quite nicely with Williams p+1
   factoring method. */

void ssh_mp_reduced_lucas(SshInt *op_dest, const SshInt *op_e,
                          const SshInt *op_p,
                          const SshInt *op_n)
{
  SshInt v1, v2;
  char *bittable;
  int bit, scan_bit, maxbit;

  if (ssh_mp_cmp_ui(op_e, 0) == 0)
    {
      ssh_mp_set_ui(op_dest, 2);
      return;
    }
  
  maxbit = ssh_mp_bit_size(op_e);

  bittable = (char *)ssh_xmalloc(maxbit);
  
  bit = 0;
  scan_bit = -1;
  
  while (bit < maxbit)
    {
      scan_bit = ssh_mp_scan1(op_e, bit);
      if (scan_bit >= maxbit)
        break;

      while (bit < scan_bit)
        {
          bittable[bit] = 0;
          bit++;
        }

      bittable[bit] = 1;
      bit++;
    }

  /* Set up */
  ssh_mp_init_set(&v2, op_p);
  ssh_mp_init(&v1);
  ssh_mp_mul(&v1, op_p, op_p);
  ssh_mp_sub_ui(&v1, &v1, 2);
  ssh_mp_mod(&v1, &v1, op_n);

  /* Get the most-significant bit */
  bit--;

  while (bit--)
    {
      if (bittable[bit])
        {
          ssh_mp_mul(&v2, &v2, &v1);
          ssh_mp_sub(&v2, &v2, op_p);
          ssh_mp_mod(&v2, &v2, op_n);

          ssh_mp_mul(&v1, &v1, &v1);
          ssh_mp_sub_ui(&v1, &v1, 2);
          ssh_mp_mod(&v1, &v1, op_n);
        }
      else
        {
          ssh_mp_mul(&v1, &v2, &v1);
          ssh_mp_sub(&v1, &v1, op_p);
          ssh_mp_mod(&v1, &v1, op_n);

          ssh_mp_mul(&v2, &v2, &v2);
          ssh_mp_sub_ui(&v2, &v2, 2);
          ssh_mp_mod(&v2, &v2, op_n);
        }
    }

  /* Free bit table */
  ssh_xfree(bittable);

  ssh_mp_clear(&v1);
  ssh_mp_clear(&v2);

  ssh_mp_set(op_dest, &v2);
}
 
/* Generating lucas sequences. */

void ssh_mp_lucas(SshInt *op_dest, const SshInt *op_src1,
                  const SshInt *op_src2,
                  const SshInt *k, const SshInt *modulo)
{
  SshInt u, v, inv2, t, t1, t2, t3, a;
  int bits, scan_bits, last_bit = 0, maxbits;
  unsigned char *bit_table;
  
  /* Initialize temporary variables. */
  ssh_mp_init_set_ui(&u, 1);
  ssh_mp_init_set(&v, op_src1);

  ssh_mp_init(&t);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);
  ssh_mp_init(&t3);
  ssh_mp_init_set_ui(&inv2, 2);
  ssh_mp_mod_invert(&inv2, &inv2, modulo);
  ssh_mp_init(&a);

  /* Compute a = op_src1*op_src1 - 4*op_src2 */
  ssh_mp_mul(&a, op_src1, op_src1);
  ssh_mp_mul_ui(&t, op_src2, 4);
  ssh_mp_sub(&a, &a, &t);
  ssh_mp_mod(&a, &a, modulo);
  
  /* Get the maximum bit count */
  maxbits = ssh_mp_bit_size(k);
  bits = 0;
  scan_bits = -1;

  /* Allocate for reverse bits */
  bit_table = (unsigned char *)ssh_xmalloc(maxbits);
  
  /* Get the reverse order */
  while (bits < maxbits)
    {
      scan_bits = ssh_mp_scan1(k, bits);
      if (scan_bits >= maxbits)
        break;
      
      while (bits < scan_bits)
        {
          bit_table[bits] = 0;
          bits++;
        }
          
      bit_table[bits] = 1;
      last_bit = bits;
      
      bits++;
    }

  bits = last_bit;
  
  while (bits)
    {
      bits--;
      /* Compute (u, v) = (uv (mod p), (v^2 + a)/2 (mod p)) */
      ssh_mp_mul(&t1, &u, &v);
      
      ssh_mp_mul(&t2, &v, &v);
      ssh_mp_mul(&t3, &u, &u);
      ssh_mp_mul(&t3, &t3, &a);
      ssh_mp_add(&t2, &t2, &t3);
      ssh_mp_mul(&t2, &t2, &inv2);
      
      ssh_mp_mod(&v, &t2, modulo);
      ssh_mp_mod(&u, &t1, modulo);
      
      if (bit_table[bits])
        {
          ssh_mp_mul(&t1, op_src1, &u);
          ssh_mp_add(&t1, &t1, &v);
          ssh_mp_mul(&t1, &t1, &inv2);

          ssh_mp_mul(&t2, op_src1, &v);
          ssh_mp_mul(&t3, &a, &u);
          ssh_mp_add(&t2, &t2, &t3);
          ssh_mp_mul(&t2, &t2, &inv2);

          ssh_mp_mod(&u, &t1, modulo);
          ssh_mp_mod(&v, &t2, modulo);
        }
    }

  ssh_mp_set(op_dest, &v);

  /* Free allocated memory */
  ssh_xfree(bit_table);
  
  ssh_mp_clear(&t);
  ssh_mp_clear(&u);
  ssh_mp_clear(&v);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
  ssh_mp_clear(&t3);
  ssh_mp_clear(&a);
  ssh_mp_clear(&inv2);
  
}
/* Modular square roots, with lucas sequence. Works fine, and is quite
   fast. If possible select the modulus so that you can use the special
   cases. */

int ssh_mp_mod_sqrt(SshInt *op_dest, const SshInt *op_src,
                    const SshInt *modulo)
{
  SshInt t, t1, t2, inv2;

  /* Fast check for 0, which would otherwise confuse the system
     quite a bit. */
  if (ssh_mp_cmp_ui(op_src, 0) == 0)
    {
      ssh_mp_set_ui(op_dest, 0);
      return 1;
    }
  
  /* There is no square root if this is true. */
  if (ssh_mp_legendre(op_src, modulo) == -1)
    {
      ssh_mp_set_ui(op_dest, 0);
      return 0;
    }

  /* Initialize temporary variables. */
  ssh_mp_init(&t);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);
  ssh_mp_init_set_ui(&inv2, 2);

  /* Test the special cases first */
  
  /* if congruence modulo = 3 (mod 4) holds */
  ssh_mp_mod_ui2(&t, modulo, 4);
  if (ssh_mp_cmp_ui(&t, 3) == 0)
    {
      ssh_mp_sub_ui(&t, modulo, 3);
      ssh_mp_div_2exp(&t, &t, 2);
      ssh_mp_add_ui(&t, &t, 1);
      ssh_mp_powm(op_dest, op_src, &t, modulo);
      goto end;
    }

  /* if congruence modulo = 5 (mod 8) holds */
  ssh_mp_mod_ui2(&t, modulo, 8);
  if (ssh_mp_cmp_ui(&t, 5) == 0)
    {
      ssh_mp_sub_ui(&t, modulo, 5);
      ssh_mp_div_2exp(&t, &t, 3);
      
      ssh_mp_mul_ui(&t1, op_src, 2);
      ssh_mp_powm(&t2, &t1, &t, modulo);

      ssh_mp_mul(&t, &t2, &t2);
      ssh_mp_mul(&t, &t, op_src);
      ssh_mp_mul_ui(&t, &t, 2);
      ssh_mp_mod(&t, &t, modulo);

      ssh_mp_sub_ui(&t, &t, 1);
      ssh_mp_mul(&t, &t, &t2);
      ssh_mp_mul(&t, &t, op_src);
      ssh_mp_mod(op_dest, &t, modulo);

      goto end;
    }
  
  /* Modulo = 1 (mod 4). */

  /* Find t^2 - 4(op_src) such that it has not square root (mod modulo) */
  ssh_mp_mul_ui(&t, op_src, 4);
  ssh_mp_set_ui(&t1, 1);

  while (ssh_mp_cmp(&t1, modulo) <= 0)
    {
      ssh_mp_mul(&t2, &t1, &t1);
      ssh_mp_sub(&t2, &t2, &t);
      ssh_mp_mod(&t2, &t2, modulo);

      if (ssh_mp_legendre(&t2, modulo) == -1)
        break;

      ssh_mp_add_ui(&t1, &t1, 1);
    }
  
  /* Compute the square root with lucas sequence... */
  ssh_mp_add_ui(&t2, modulo, 1);
  ssh_mp_div_ui(&t2, &t2, 2);
  ssh_mp_lucas(op_dest, &t1, op_src, &t2, modulo);

  /* ...multiply with the inverse of 2 */
  ssh_mp_mod_invert(&inv2, &inv2, modulo);
  ssh_mp_mul(op_dest, op_dest, &inv2);
  ssh_mp_mod(op_dest, op_dest, modulo);
  
end:

  /* Clear temporary variables */
  ssh_mp_clear(&t);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);

  ssh_mp_clear(&inv2);

  return 1;
}

#endif

#if 0
/* Check the Menezes, Okamoto and Vanstone elliptic curve reduction attack
   possibility. */

Boolean ssh_mp_mov_condition(const SshInt *op_b, const SshInt *op_q,
                             const SshInt *op_r)
{
  SshInt t, i;
  Boolean mov_condition = FALSE;
  
  /* Initialize temporary variables. */
  ssh_mp_init_set_ui(&t, 1);
  
  ssh_mp_init_set(&i, op_b);

  /* Iterate the mov condition */
  while (ssh_mp_cmp_ui(&i, 0) != 0)
    {
      ssh_mp_mul(&t, &t, op_q);
      ssh_mp_mod(&t, &t, op_r);
      if (ssh_mp_cmp_ui(&t, 1) == 0)
        {
          mov_condition = TRUE;
          break;
        }

      ssh_mp_sub_ui(&i, &i, 1);
    }

  /* Clear temporary variables. */
  ssh_mp_clear(&t);
  ssh_mp_clear(&i);

  return mov_condition;
}

#endif

/* Check whether op_src is of order op_ord (mod modulo). Not used and not
   tested. */

int ssh_mp_is_order(const SshInt *op_ord, const SshInt *op_src,
                    const SshInt *modulo)
{
  SshInt t, t1;
  int i;
  int is_order = 1;
  
  /* Initialize t and t1 */
  ssh_mp_init(&t);
  ssh_mp_init(&t1);
  
  ssh_mp_powm(&t, op_src, op_ord, modulo);
  if (ssh_mp_cmp_ui(&t, 1) != 0)
    {
      is_order = 0;
      goto end;
    }
  
  /* Trial division factoring algorithm... this shouldn't need better (?) */
  ssh_mp_set(&t, op_ord);
  for (i = 0; ssh_prime_table[i]; i++)
    {
      /* Check whether op_src is divisible by a prime... */
      ssh_mp_mod_ui2(&t1, &t, ssh_prime_table[i]);
      if (ssh_mp_cmp_ui(&t1, 0) == 0)
        {
          /* This really isn't necessary but speeds up possibly a bit. */
          do {
            ssh_mp_div_ui(&t, &t, ssh_prime_table[i]);
            ssh_mp_mod_ui2(&t1, &t, ssh_prime_table[i]);
          } while (ssh_mp_cmp_ui(&t1, 0) == 0);
            
          ssh_mp_powm_expui(&t, op_src, ssh_prime_table[i], modulo);
          if (ssh_mp_cmp_ui(&t, 1) == 0)
            {
              is_order = 0;
              break;
            }
        }
    }
end:
  
  ssh_mp_clear(&t);
  ssh_mp_clear(&t1);
  
  /* Could be of the order of op_ord */
  return is_order;
}

/* Find a random generator of order 'order' modulo 'modulo'. */

Boolean ssh_mp_random_generator(SshInt *g, SshInt *order, SshInt *modulo,
                                SshRandomState state)
{
  SshInt aux, t;
  int bits;

  ssh_mp_init(&aux);
  ssh_mp_init(&t);

  ssh_mp_sub_ui(&aux, modulo, 1);
  ssh_mp_mod(&t, &aux, order);

  if (ssh_mp_cmp_ui(&t, 0) != 0)
    {
      ssh_mp_clear(&aux);
      ssh_mp_clear(&t);
      return FALSE;
    }

  ssh_mp_div_q(&t, &aux, order);
  bits = ssh_mp_get_size(modulo, 2);
  
  while (1)
    {
      ssh_mp_random_integer(g, state, bits);
      ssh_mp_mod(g, g, modulo);
      ssh_mp_powm(g, g, &t, modulo);

      if (ssh_mp_cmp_ui(g, 1) != 0)
        break;
    }

  /* Check. */
  ssh_mp_powm(&aux, g, order, modulo);
  if (ssh_mp_cmp_ui(&aux, 1) != 0)
    {
      ssh_mp_clear(&aux);
      ssh_mp_clear(&t);
      return FALSE;
    }

  ssh_mp_clear(&aux);
  ssh_mp_clear(&t);

  return TRUE;
}

/* genmp.c */

