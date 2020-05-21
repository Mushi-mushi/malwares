/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon May  6 00:13:23 1996 [huima]

  Generic multiple precision functions that are not found in GMP library.

  NOTE: this file will soon contain much less functionality, some
        functions will be moved to sshmath directory, where they are
        more appropriately handled.

        Also the prime table will be removed, it is cumbersome, and given
        modern computers sieving in real time 1000 or so primes is a
        trivial task. (The SshSieve and functions does this with
        reasonable efficiency.)
        
  */

/*
 * $Id: genmp.h,v 1.23 1999/04/29 13:38:06 huima Exp $
 * $Log: genmp.h,v $
 * $EndLog$
 */

#ifndef GENMP_H
#define GENMP_H

/* This is needed to find linearization routines which lie in sshutil
   library, but used to be here. However, they are of greater use
   in util library. */
#include "sshmpaux.h"

/* Our prime table (one might want to use the sieve routines later). */

#define SSH_MAX_PRIMES_IN_TABLE 1051

extern const unsigned int ssh_prime_table[SSH_MAX_PRIMES_IN_TABLE + 1];

/* Generates a random integer of the desired number of bits. */

void ssh_mp_random_integer(SshInt *ret, SshRandomState state,
                           unsigned int bits);

/* Makes and returns a random pseudo prime of the desired number of bits.
   Note that the random number generator must be initialized properly
   before using this.

   The generated prime will have the highest bit set, and will have
   the two lowest bits set.

   Primality is tested with Miller-Rabin test, ret thus having
   probability about 1 - 2^(-50) (or more) of being a true prime.
   */
void ssh_mp_random_prime(SshInt *ret, SshRandomState state,
                         unsigned int bits);

#if 0
/* Find next prime from start. Useful when in need of field that contains
   element start. */

void ssh_mp_next_prime(SshInt *ret, SshInt *start);
#endif

/* Similar to the ssh_mp_random_prime, except that the 'strong' pseudo
   prime is returned. Uses method described in P1363 working draft. 

   'big_bits' tells how many bits are in the 'prime' and 'small_bits' how
   many bits in the 'div'. Note that 'prime' - 1 = 0 mod 'div'. 

   This method generates good primes for RSA or other factorization based
   cryptosystems. For discrete log based systems this isn't exactly
   neccessary.
   */

void ssh_mp_strong_p1363_random_prime(SshInt *prime, SshInt *div,
                                      int big_bits, int small_bits,
                                      SshRandomState state);

/* Generate a strong random prime, where 'prime' = 'order' * u + 1. Similar
   to the P1363 method but takes less time and is almost as 'strong'. The
   P1363 strong primes satisfy some other facts, but in practice these
   primes seem as good with discrete log based cryptosystems. */

void ssh_mp_random_strong_prime(SshInt *prime,
                                SshInt *order,
                                int prime_bits, int order_bits,
                                SshRandomState state);

/* Modular invert with positive results. */

int ssh_mp_mod_invert(SshInt *op_dest, const SshInt *op_src,
                      const SshInt *modulo);

/* Random number with special modulus */

void ssh_mp_mod_random(SshInt *op, const SshInt *modulo, SshRandomState state);

/* Generate a random integer with entropy at most _bits_ bits. The atmost,
   means that the actual number of bits depends whether the modulus is
   smaller in bits than the _bits_.  */
void ssh_mp_mod_random_entropy(SshInt *op, const SshInt *modulo,
                               SshRandomState state,
                               unsigned int bits);
                               

#if 0
/* Lucas functions */

void ssh_mp_reduced_lucas(SshInt *op_dest, const SshInt *op_e,
                          const SshInt *op_p, const SshInt *op_n);

void ssh_mp_lucas(SshInt *op_dest, const SshInt *op_src1,
                  const SshInt *op_src2,
                  const SshInt *k, const SshInt *modulo);

/* Modular square root */

int ssh_mp_mod_sqrt(SshInt *op_dest, const SshInt *op_src,
                    const SshInt *modulo);
#endif

/* Check the MOV condition, for elliptic curves */

Boolean ssh_mp_mov_condition(const SshInt *b,
                             const SshInt *q, const SshInt *r);

/* Check whether op_src is of order op_ord mod modulo */

int ssh_mp_is_order(const SshInt *op_ord, const SshInt *op_src,
                    const SshInt *modulo);

/* Find a random generator of order 'order' modulo 'modulo'. */

Boolean ssh_mp_random_generator(SshInt *g, SshInt *order, SshInt *modulo,
                                SshRandomState state);
#endif /* GENMP_H */
