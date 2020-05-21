/*

  sshmp.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Jan 16 18:23:36 1998 [mkojo]

  SSH Multiple Precision arithmetic library with fast modular arithmetic
  interface. 

  Purpose of this library is to achieve fast general modulus
  modular arithmetic. Modular, or finite field, arithmetic is main
  ingredient to fast public key cryptosystems. Nevertheless, this
  library routines are not cryptographical, in a sense, that they
  would implement any cryptographical features. Rather, you have to
  implement the cryptographical protocols, and algorithms, over these
  routines. 
  
  */

/*
 * $Id: sshmp.h,v 1.17 1999/04/24 01:54:55 mkojo Exp $
 * $Log: sshmp.h,v $
 * $EndLog$
 */

#ifndef SSHMP_H
#define SSHMP_H

#include "sshmath-types.h"

/* SSH MP data structures. This information is usually best left alone. */ 

/* The basic definition of a Ssh Integer. */
typedef struct SshIntRec
{
  /* To make the code "harder" to read, we use short names
       m denotes the amount of memory allocated for a integer (in words)
       n denotes the amount of memory used by the integer (in words)
     */
  unsigned int m;
  unsigned int n;

  /* We use one additional word for sign. */
  Boolean sign;

  /* The array of integer words in base 2. */
  SshWord *v;
} SshInt;

/* SSH Integer Cell. */
typedef SshInt SshIntC[1];

/* Definitions of a Ssh Integer Moduli. */
typedef struct SshIntModuliRec
{
  /* Note: Current implementation uses only Montgomery representation,
     however, the interface could easily allow use of several other classes
     of fast modular arithmetic. */
  
  /* Necessary details needed for Montgomery representation, if available. */
  
  /* First word (least significant) of -m^-1 (mod 2^n), where m is the
     moduli. */
  SshWord mp;

  /* The modulus. */
  SshWord *m, *d;
  unsigned int m_n, shift;

  /* Workspaces. */
  SshWord     *karatsuba_work_space,  *work_space;
  unsigned int karatsuba_work_space_n, work_space_n;
} SshIntModuli;

/* Definition of a Ssh Integer Modulo a Integer Q. */
typedef struct SshIntModQRec
{
  /* Basic integer information. That is
       n denotes the number of used words
       v denotes the array where these words are stored
     */
  unsigned int n;
  SshWord *v;

  /* Modulus information. */
  const SshIntModuli *m;
} SshIntModQ;

/* Some memory management. */

SshInt *ssh_mp_malloc(void);
void ssh_mp_free(SshInt *op);

/* This function makes the integer 'op' to have new_size words of memory
   reserved, even if it doesn't need it at the moment. This cannot truncate
   the size of an allocated memory space for an integer, thus should be
   used only when known that a lot of memory is needed.

   This function is not needed to be called ever, library calls it itself
   if necessary.
   */
void ssh_mp_realloc(SshInt *op, unsigned int new_size);

/* The basic integer manipulation functions. */

/* Following routine initializes a multiple precision integer. This function
   must be called before any other use of SshInt structure. */
void ssh_mp_init(SshInt *op);

/* After the SshInt structure has been used, and is not needed anymore one
   could free it with this function. Any new use of the given structure
   must preceed again a call to ssh_mp_init function. */
void ssh_mp_clear(SshInt *op);

/* Clear a bit in op. */
void ssh_mp_clr_bit(SshInt *op, unsigned int n);

/* Get something out of SshInt. */

/* Get the lsb-word out of the integer. */
SshWord ssh_mp_get_ui(const SshInt *op);
/* Get the lsb-signed word (the sign is given by the sign of the integer)
   out of the integer. */
SignedSshWord ssh_mp_get_si(const SshInt *op);
/* Return the bit in position 2^bit in bn. */
unsigned int ssh_mp_get_bit(const SshInt *op, unsigned int bit);
/* Get of some base out of op. */
char *ssh_mp_get_str(char *ret_str, SshWord base, const SshInt *op);
/* Get the size in given 'base'. User of this function should notice, that
   the returned value will be one off. That is, the returned value gives
   the value e so that base^e > op and base^{e-1} <= op. */
unsigned int ssh_mp_get_size(const SshInt *op, SshWord base);

/* Put something into SshInt. */

/* Set op into ret. */
void ssh_mp_set(SshInt *ret, const SshInt *op);
/* Set unsigned int (of same size as our word) u into op. */
void ssh_mp_set_ui(SshInt *op, SshWord u);
/* Set int (of same size as our word) s into op. */
void ssh_mp_set_si(SshInt *op, SignedSshWord s);
/* Set the bit in position 2^bit as one. */
void ssh_mp_set_bit(SshInt *op, unsigned int bit);
/* Get put base-10 XXX integer (represented as a null-terminated string)
   into op. Returns 0 if error, 1 if successful. */
int ssh_mp_set_str(SshInt *op, const char *str, SshWord base);

/* Corresponding initialization functions. */
void ssh_mp_init_set(SshInt *ret, const SshInt *op);
void ssh_mp_init_set_ui(SshInt *ret, SshWord u);
void ssh_mp_init_set_si(SshInt *ret, SignedSshWord s);
int ssh_mp_init_set_str(SshInt *ret, const char *str, unsigned int base);

/* Scanning. Use the get_bit and set_bit routines rather. */
/* Scan for bit 0, starting at bit. Moving upwards. */
unsigned int ssh_mp_scan0(const SshInt *op, unsigned int bit);
/* Scan for bit 1, starting at bit. Moving upwards. */
unsigned int ssh_mp_scan1(const SshInt *op, unsigned int bit);

#if 1
void ssh_mp_out_str(FILE *fp, unsigned int base, const SshInt *op);
#endif

/* Routines to linearize the integer into a octet string. Note, that these
   routines do not handle the signs correctly, at the moment. */
void ssh_mp_get_buf(unsigned char *buf, size_t buf_length,
                    const SshInt *op);
void ssh_mp_set_buf(SshInt *ret, const unsigned char *buf, size_t buf_length);

/* Handle signs. */
/* Equals to ret = -op. */
void ssh_mp_neg(SshInt *ret, const SshInt *op);
/* Equals to ret = |op|, that is, ret is the absolute value of op. */
void ssh_mp_abs(SshInt *ret, const SshInt *op);
/* Returns -1 if negative, 1 otherwise. */
int ssh_mp_signum(const SshInt *op);

/* Basic binary (boolean) arithmetic operations. */

/* Equals to ret = op1 & op2, in C language. */
void ssh_mp_and(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = op1 ^ op2, in C language. */
void ssh_mp_xor(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = op1 | op2, in C language. */
void ssh_mp_or(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = ~op, in C language. */
void ssh_mp_com(SshInt *ret, const SshInt *op);

/* Comparison routines. */

/* Returns 0 if op1 = op2, 1 if op1 > op2, -1 if op1 < op2. */
int ssh_mp_cmp(const SshInt *op1, const SshInt *op2);
/* Returns 0 if op = u, 1 if op > u, -1 if op < u. */
int ssh_mp_cmp_ui(const SshInt *op, SshWord u);
/* Returns 0 if op = s, 1 if op > s, -1 if op < s. */
int ssh_mp_cmp_si(const SshInt *op, SignedSshWord s);

/* The very basic arithmetic operations of ordinary integer. */

/* Equals to ret = op1 + op2. */
void ssh_mp_add(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = op1 - op2. */
void ssh_mp_sub(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = op + u. */
void ssh_mp_add_ui(SshInt *ret, const SshInt *op, SshWord u);
/* Equals to ret = op - u. */
void ssh_mp_sub_ui(SshInt *ret, const SshInt *op, SshWord u);

/* Multiplication, squaring and division routines. */

/* Equals to ret = op1 * op2. */
void ssh_mp_mul(SshInt *ret, const SshInt *op1, const SshInt *op2);
/* Equals to ret = op * u. */
void ssh_mp_mul_ui(SshInt *ret, const SshInt *op, SshWord u);
/* Equals to ret = op^2. Note: This function is faster than ordinary
   multiplication, thus in places where computation of squares is high
   one should use this function. All routines in this library are
   optimized in this sense. */
void ssh_mp_square(SshInt *ret, const SshInt *op);

/* Warning! This version does not have multiple rounding modes, and
   you should be aware the way that rounding happens within these
   functions. */

/* Equals to op1 = q * op2 + r. Rounding towards zero. */
void ssh_mp_div(SshInt *q, SshInt *r, const SshInt *op1, const SshInt *op2);
/* Equals to (op1 - (op1 % op2)) / op2 = q. Rounding towards zero. */
void ssh_mp_div_q(SshInt *q, const SshInt *op1, const SshInt *op2);
/* Equals to r == op1 (mod op2). Sign of r is always positive, and
   it is assumed that op2 has positive sign. */
void ssh_mp_mod(SshInt *r, const SshInt *op1, const SshInt *op2);
/* Equals to op = q * u + r, where r is returned. Rounding towards zero. */
SshWord ssh_mp_div_ui(SshInt *q, const SshInt *op, SshWord u);
/* Equals to r == op (mod u), where r is returned. Use this function
   rather the next one. */
SshWord ssh_mp_mod_ui(const SshInt *op, SshWord u);
/* Equal to previous function. Returns the remainder in ret, and
   it has positive sign. */
SshWord ssh_mp_mod_ui2(SshInt *ret, const SshInt *op, SshWord u);

/* The basic routines which compute with 2^n's, that is basically
   do shifting. */

/* Mod_2exp returns in r only positive values. */
void ssh_mp_mod_2exp(SshInt *r, const SshInt *op, unsigned int bits);
void ssh_mp_div_2exp(SshInt *q, const SshInt *op, unsigned int bits);
void ssh_mp_mul_2exp(SshInt *ret, const SshInt *op, unsigned int bits);

/* Random numbers (for testing etc. not for cryptography) */

/* Generate random number op < 2^bits. */
void ssh_mp_rand(SshInt *op, unsigned int bits);
/* Generate random number op < 2^bits, which has bits/weigth probability
   that any bit 2^k, k < bits, is set. */
void ssh_mp_rand_w(SshInt *op, unsigned int bits, unsigned int weigth);

/* Some elementary integer operations. */

/* Computation of ret = g^e, which gives usually rather large
   return values. */
void ssh_mp_pow(SshInt *ret, const SshInt *g, const SshInt *e);

/* d = gcd(a, b), that is, this computes the greatest common divisor. */
void ssh_mp_gcd(SshInt *d, const SshInt *a, const SshInt *b);

/* Computes d = u*a + v*b, where a, b are given as input. */
void ssh_mp_gcdext(SshInt *d, SshInt *u, SshInt *v,
                   const SshInt *a, const SshInt *b);

/* op*inv == 1 (mod m), where op and m are given as input. */
Boolean ssh_mp_invert(SshInt *inv, const SshInt *op, const SshInt *m);

/* Following routines all compute (a/b) that is the Kronecker - Jacobi
   - Legendre symbol. In a case when b is prime we find out whether a
   is a quadratic residue or not. (These all use the same routine, thus
   there is no other need, but completeness, to include them all).*/
int ssh_mp_kronecker(const SshInt *a, const SshInt *b);
int ssh_mp_jacobi(const SshInt *a, const SshInt *b);
int ssh_mp_legendre(const SshInt *a, const SshInt *b);

/* Compute ret = op^(1/2) (mod p). That is, compute modular square
   root of op if possible. Returns FALSE if op is not quadratic
   residue modulo p. Although it is possible in some cases to compute
   modular sqrt even if p is not prime, it is not guaranteed that this
   function returns anything sensible in those cases. */
Boolean ssh_mp_mod_sqrt(SshInt *ret, const SshInt *op, const SshInt *p);

/* Solves sqrt^2 = op, where op is given as input. Works with integers, and
   the output thus is only an approximation. */
void ssh_mp_sqrt(SshInt *sqrt_out, const SshInt *op);

/* Routine to check whether a given value 'op' is perfect square, that is
   if op = t^2. Returns 1 if it is, 0 if not. */
int ssh_mp_is_perfect_square(const SshInt *op);

#if 1
/* XXX Dump structure internal data. */
void ssh_mp_dump(const SshInt *bn);
#endif

/* Following routines implement the same thing. Exponentiation modulo a
   large integer. Fastest ones are the bsw routines.

   The routine which has best running times is the selected for general
   usage. However, it doesn't support even moduli.
   */

/* This is a special heuristic for faster modular exponentiation. If you
   know that you are using certain moduli and generator for many
   exponentiations it pays to do some precomputation. This is
   only very minor computation, and takes into account the desire to
   keep from allocating very much. Basically it takes at most 512
   integers for the table, which may seem like a lot.

   At the moment this isn't very much faster than the other routines,
   as it uses pretty much same building blocks. This could, however,
   be speeded up somewhat. So the idea seems good. 
   */
typedef struct
{
  /* Wether this context is initialized or not. */
  Boolean defined;
  /* A large table for computed values. */
  unsigned int table_size;
  unsigned int table_bits;
  SshIntModQ *table;
  /* The moduli under the table was computed. */
  SshIntModuli mod;
} SshMpPowmBase;

/* Initialize the base structure, performs the precomputation (which
   is very fast). */
void ssh_mp_powm_with_base_init(SshInt *g, SshInt *m,
                                SshMpPowmBase *base);
/* Clears the base. */
void ssh_mp_powm_with_base_clear(SshMpPowmBase *base);


/* Following functions are the general modular exponentiation functions. */
void ssh_mp_powm_naive(SshInt *op, const SshInt *g, const SshInt *e,
                       const SshInt *m);
void ssh_mp_powm_bsw(SshInt *op, const SshInt *g, const SshInt *e,
                     const SshInt *m);
void ssh_mp_powm_naive_mont(SshInt *op, const SshInt *g, const SshInt *e,
                            const SshInt *m);
void ssh_mp_powm_bsw_mont(SshInt *op, const SshInt *g, const SshInt *e,
                          const SshInt *m);

/* This is the general modular exponentiation with support for precomputed
   base. */
void ssh_mp_powm_with_base_bsw_mont(SshInt *ret, const SshInt *e,
                                    SshMpPowmBase *base);

/* Specialized routines for computing g^e (mod m), where g is very small. */
void ssh_mp_powm_naive_ui(SshInt *op, SshWord g, const SshInt *e,
                          const SshInt *m);
void ssh_mp_powm_naive_mont_ui(SshInt *ret, SshWord g,
                               const SshInt *e, const SshInt *m);
void ssh_mp_powm_naive_mont_base2(SshInt *ret, const SshInt *e,
                                  const SshInt *m);

/* Exponentiation with a very small exponent. */
void ssh_mp_powm_naive_expui(SshInt *op, const SshInt *g, SshWord e,
                             const SshInt *m);

/* Select your favourite, or fastest, routine here. */
#define ssh_mp_powm           ssh_mp_powm_bsw_mont
#define ssh_mp_powm_ui        ssh_mp_powm_naive_mont_ui
#define ssh_mp_powm_base2     ssh_mp_powm_naive_mont_base2
#define ssh_mp_powm_expui     ssh_mp_powm_naive_expui
#define ssh_mp_powm_with_base ssh_mp_powm_with_base_bsw_mont

/* Intermediate arithmetic routines. */

/* Probabilistic primality test. Uses the Rabin-Miller test, of
   probability (1/4)^limit, approximately, to check whether op is
   prime. This function iterates the test limit times to see, and also
   uses Fermat test for base-2 to speed things up. It is recommended
   that this function is used after a trial division routine. */
int ssh_mp_is_probable_prime(const SshInt *op, unsigned int limit);

/* A routine which seeks until finds a prime number that is next one
   in succession to start. Notice, that this function does nothing
   that would bias the result (XXX hopefully!), thus one can use
   this routine in cryptographical applications.

   This function outputs to 'p' the next prime found. If error occurs,
   such as no prime could be found, it returns FALSE. */
Boolean ssh_mp_next_prime(SshInt *p, const SshInt *start);

/* XXX prime searchers that seek for large 'safe' primes. */

/* Following group of routines implements the interface for fast modular
   arithmetic. Indeed, all modular arithmetic code, which uses the same
   moduli for some set of values for longer period of time should use
   this interface. Often the code under this interface is worth the
   extra effort. 

   XXX This version doesn't work with even moduli. This is not a
   serious problem. In fact, it is hard to find any sensible
   occurrence of a problem which needs integers mod k*2^n. And when
   such is found, we would notice, that it can be done as easily
   without this interface for most cases.

   */

/* This defines the use of workspace. That is, the workspace will be
   allocated (to minimize the needed allocations in modular arithmetic)
   to the modulus structure.
   
   You can of course undefine it, and then most allocation will be handled
   dynamically when doing computations. The amount of memory used is not
   prohibitive. */
#define SSHMATH_USE_WORKSPACE 

/* Initialize the moduli. That is, this translates the moduli given in
   integer form to faster representation m. */
Boolean ssh_mpm_init_m(SshIntModuli *m, const SshInt *op);

/* Clear/free the modulus. */
void ssh_mpm_clear_m(SshIntModuli *m);

/* Initialize a new integer modulo m. Notice that the moduli must be known
   when this is called. */
void ssh_mpm_init(SshIntModQ *op, const SshIntModuli *m);

/* Clear the modulo m integer. */
void ssh_mpm_clear(SshIntModQ *op);

/* Convert a SshInt into a value modulo m. */
void ssh_mpm_set_mp(SshIntModQ *ret, const SshInt *op);
/* Copy one value modulo m into another. I.e. ret = op. */
void ssh_mpm_set(SshIntModQ *ret, const SshIntModQ *op);

/* Convert a value modulo m into SshInt. */
void ssh_mp_set_mpm(SshInt *ret, const SshIntModQ *op);
void ssh_mp_set_m(SshInt *ret, const SshIntModuli *m);

/* Comparison function. One should not rely on the fact that -1 and 1
   mean anything but that the inputs are different. 0 means always the
   the inputs are same. */
int ssh_mpm_cmp(SshIntModQ *op1, SshIntModQ *op2);
  
/* Basic arithmetic in modulo m representation. */

/* Fast modular addition and subtraction, keeps the values always within
   the modular domain. */
void ssh_mpm_add(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2);
void ssh_mpm_sub(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2);

/* Fast multiplication which keeps the values within modular domain. */
void ssh_mpm_mul(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2);
/* Fast multiplication by small integer. */
void ssh_mpm_mul_ui(SshIntModQ *ret, const SshIntModQ *op, SshWord u);
/* Very quick squaring operation. */
void ssh_mpm_square(SshIntModQ *ret, const SshIntModQ *op);

/* Routines for handling modular divisions by powers of 2.

   These routines are meant mainly to be used for small powers and thus
   are not fastest for larger ones. However, for very small powers these
   work with small amount of operations. 
   */
void ssh_mpm_div_2exp(SshIntModQ *ret, const SshIntModQ *op,
                      unsigned int exp);
/* Very simple, and fast, multiplication by powers of 2. */
void ssh_mpm_mul_2exp(SshIntModQ *ret, const SshIntModQ *op,
                      unsigned int exp);

/* This inversion is not fast, but we assume that you don't need faster
   implementation. It is possible to write faster inversion later. */
Boolean ssh_mpm_invert(SshIntModQ *ret, const SshIntModQ *op);

/* XXX Following routines are implemented if needed. These can be
   simulated easily by the integer routines. */
int ssh_mpm_kronecker(const SshIntModQ *ret);
Boolean ssh_mpm_gcd(SshIntModQ *ret, const SshIntModQ *op);
Boolean ssh_mpm_sqrt(SshIntModQ *ret, const SshIntModQ *op);

#if 1
/* XXX Dump the structure internal data... */
void ssh_mpm_dump(const SshIntModQ *op);
#endif

/**********************************************************************/
/* Rationals? Do we need 'em? Probably SshFloat's upto reasonable precision
   does the same job. */
/**********************************************************************/
/* Routines for SshFloat's. */
/*
  At least following routines should be implemented (implementation is a
  bit tricky, but can be done):
  ssh_finit();
  ssh_fclear();
  ssh_fneg();
  ssh_fabs();
  ssh_fset();
  ssh_fget();
  ssh_fadd();
  ssh_fsub();
  ssh_fmul();
  ssh_fsquare();
  ssh_fdiv();
  ssh_fsqrt();
  ssh_fpow();
  ssh_fsin();
  ssh_fcos();
  ssh_ftan();
  ssh_fexp();
  ssh_fln();
  ssh_fpi();
  ssh_fln2();
  */

/**********************************************************************/
/* Routines for SshComplex's.*/
/*
  At least following routines should be implemented (these are easy after
  SshFloat's are implemented):
  ssh_cinit();
  ssh_cclear();
  ssh_cset();
  ssh_cget();
  ssh_cneg();
  ssh_cre();
  ssh_cim();
  ssh_cadd();
  ssh_csub();
  ssh_cmul();
  ssh_cdiv();
  ssh_csquare();
  ssh_cpow();
  ssh_croot();
 */
/**********************************************************************/
/* Polynomial routines over integers modulo a prime. That is, we can use
   the routines given by ssh_mpm_* and thus get efficient polynomial
   arithmetic over finite fields.

   SshPolyModQ
   */
/* Fast implementation should use FFT etc, but we are satisfied with just
   Karatsuba methods. Nothing fancier. */
/**********************************************************************/
/* Polynomial routines over complex numbers.
   SshComplexPoly
 */
/* These are directly analoguous to the ModQ versions. */
/**********************************************************************/
/* Fourier series routines over complex numbers.
   SshFourier
 */
/* These are needed in some computations, but have very low priority. But
   probably at some point I will write them. */
#endif /* BIGNUM_H */

