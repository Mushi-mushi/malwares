/*

  sieve.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996-98 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu May 14 23:00:19 1998 [mkojo]

  Sieve for small primes.

  Purpose of this file is to allow any application an almost endless
  source of small primes. E.g. you don't need to table them, or anything,
  just compute them with this program when needed and then use 'em.

  This code is reasonably fast, and compared to large integer arithmetic,
  for example, this won't slow down anything. 

  OBJECTIVE:

    Replace the old SSH large prime seeking code with code that
    uses SshSieve and thus probably works faster and is cleaner.
  
  */

/*
 * $Id: sieve.h,v 1.2 1998/06/24 13:26:20 kivinen Exp $
 * $Log: sieve.h,v $
 * $EndLog$
 */

#ifndef SIEVE_H
#define SIEVE_H

/* The sieve data structure. */
typedef struct
{
  unsigned int len;
  SshWord *table;
  unsigned int count;
} SshSieve;

/* Prototypes. */

/* XXX */
void ssh_sieve_allocate_ui(SshSieve *sieve, unsigned int x,
			   unsigned int memory_limit);
void ssh_sieve_allocate(SshSieve *sieve, 
			unsigned int memory_limit);

/* Find next prime to x, e.g. prime p that is larger than x and there
   is no small prime between them. Returns 0 if sieve doesn't
   contain enough primes. */
unsigned long ssh_sieve_next_prime(unsigned long x, SshSieve *sieve);

/* Find the largest prime this sieve contains. */
unsigned long ssh_sieve_last_prime(SshSieve *sieve);
unsigned long ssh_sieve_prime_count(SshSieve *sieve);

/* Free the sieve data structure. */
void ssh_sieve_free(SshSieve *sieve);

#endif /* SIEVE_H */
