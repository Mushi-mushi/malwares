/*
  t-test-ec.c

  Author Mika Kojo <mkojo@ssh.fi>
  Copyright (c) 1998 SSH Communications Security, Ltd.
                All rights reserved.

  Test file for some elliptic curve and GF(2^n) arithmetics. Note that
  this implementation is for testing only. The real implementation
  will be based on this but will be faster (uses faster GF(2^n)
  arithmetics).
 
  */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "gf2n.h"
#include "sieve.h"
#include "timeit.h"

#if 1
void test_function_gf2n(int t1, int t2)
{
  SshGF2nElement a, b, c, d;
  SshGF2nModuli  m;
  int i;
  int bits[3];
  TimeIt tmit;

  bits[0] = 0;
  bits[1] = t1;
  bits[2] = t2;
  
  ssh_gf2n_init_mod_bits(&m, bits, 3);

  ssh_gf2n_init(&a, &m);
  ssh_gf2n_init(&b, &m);
  ssh_gf2n_init(&c, &m);
  ssh_gf2n_init(&d, &m);

  printf("Modulus: ");
  ssh_gf2n_mod_pretty_print(&m);
  printf("\n");

  ssh_gf2n_set_ui(&a, random());
  /* ssh_gf2n_poor_rand(&a); */
  
  ssh_gf2n_invert(&b, &a);

  /* Note ssh_gf2n_mul overwrites the second term... */
  ssh_gf2n_set(&c, &a);
  ssh_gf2n_mul(&d, &c, &b);

  printf(" a * a^-1 = ");
  ssh_gf2n_hex_dump(&d);
  printf("\n");

  printf(" a     = ");
  ssh_gf2n_hex_dump(&a);
  printf("\n a^-1  = ");
  ssh_gf2n_hex_dump(&b);
  printf("\n");

  /* Check that squaring and multiplication does the same job. */

  ssh_gf2n_set(&a, &b);
  ssh_gf2n_set(&d, &b);
  ssh_gf2n_mul(&c, &a, &d);

  printf(" b * b = ");
  ssh_gf2n_hex_dump(&c);
  printf("\n");

  ssh_gf2n_square(&c, &b);
  printf(" b^2   = ");
  ssh_gf2n_hex_dump(&c);
  printf("\n");
  
  printf("Timing...\n");
  
  start_timing(&tmit);

  ssh_gf2n_set(&d, &b);
  ssh_gf2n_set(&c, &b);
  
  for (i = 0; i < 10000; i++)
    {
      ssh_gf2n_set(&a, &c);
      ssh_gf2n_mul(&c, &a, &d);
    }

  check_timing(&tmit);

  ssh_gf2n_hex_dump(&c);
  printf("\n");
  
  printf("Multiplications took %.8f seconds (on average).\n",
         tmit.real_secs / i);

  start_timing(&tmit);

  ssh_gf2n_set(&c, &b);
  
  for (i = 0; i < 10000; i++)
    {
      ssh_gf2n_set(&b, &c);
      ssh_gf2n_square(&c, &b);
    }

  check_timing(&tmit);

  ssh_gf2n_hex_dump(&c);
  printf("\n");
  
  printf("Squarings took %.8f seconds (on average).\n", tmit.real_secs / i);
  
  start_timing(&tmit);

#if 1
  for (i = 0; i < 10000; i++)
    {
      ssh_gf2n_set(&d, &b);
      ssh_gf2n_invert(&a, &d);
      ssh_gf2n_set(&d, &a);
    }

  check_timing(&tmit);

  printf("Inversions took %.8f seconds (on average).\n", tmit.real_secs / i);
#endif
  
  ssh_gf2n_clear(&a);
  ssh_gf2n_clear(&b);
  ssh_gf2n_clear(&c);
  ssh_gf2n_clear(&d);
  
  ssh_gf2n_clear_mod(&m);
}
#endif

void test_function(int t1, int t2)
{
  SshBPoly a, b, c, d, m;
  int i;
  TimeIt tmit;
  
  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  ssh_bpoly_init(&d);
  ssh_bpoly_init(&m);

  /* Compute the trinomial. */
  ssh_bpoly_set_bit(&m, 0);
  ssh_bpoly_set_bit(&m, t1);
  ssh_bpoly_set_bit(&m, t2);

  printf("Modulus: ");
  ssh_bpoly_hex_dump(&m);
  printf("\n");
  
  /* Find a random value. */
  ssh_bpoly_set_ui(&a, random());
  ssh_bpoly_invert(&b, &a, &m);

  ssh_bpoly_mul(&d, &a, &b);
  ssh_bpoly_mod(&d, &d, &m);

  printf("a*a^-1 = ");
  ssh_bpoly_hex_dump(&d);
  printf("\n");

  printf("a     = ");
  ssh_bpoly_hex_dump(&a);
  printf("\n");
  printf("a^-1  = ");
  ssh_bpoly_hex_dump(&b);
  printf("\n");

  /* Check that squaring and multiplication does the same job. */

  ssh_bpoly_set(&a, &b);
  ssh_bpoly_set(&d, &b);
  ssh_bpoly_mul(&c, &a, &d);
  ssh_bpoly_mod(&c, &c, &m);

  printf("b * b = ");
  ssh_bpoly_hex_dump(&c);
  printf("\n");

  ssh_bpoly_square(&c, &b);
  ssh_bpoly_mod(&c, &c, &m);
  
  printf("b^2   = ");
  ssh_bpoly_hex_dump(&c);
  printf("\n");
  
  printf("Timing...\n");
  
  start_timing(&tmit);

  ssh_bpoly_set(&d, &b);
  ssh_bpoly_set(&c, &b);
  
  for (i = 0; i < 100; i++)
    {
      ssh_bpoly_set(&a, &c);
      ssh_bpoly_mul(&c, &a, &d);
      ssh_bpoly_mod(&c, &c, &m);
    }

  check_timing(&tmit);

  ssh_bpoly_hex_dump(&c);
  printf("\n");
  
  printf("Multiplications took %.8f seconds (on average).\n",
         tmit.real_secs / i);

  start_timing(&tmit);

  ssh_bpoly_set(&c, &b);
  
  for (i = 0; i < 100; i++)
    {
      ssh_bpoly_set(&b, &c);
      ssh_bpoly_square(&c, &b);
      ssh_bpoly_mod(&c, &c, &m);
    }

  check_timing(&tmit);

  ssh_bpoly_hex_dump(&c);
  printf("\n");
  
  printf("Squarings took %.8f seconds (on average).\n", tmit.real_secs / i);

#if 1
  
  start_timing(&tmit);

  for (i = 0; i < 100; i++)
    {
      ssh_bpoly_set(&d, &b);
      ssh_bpoly_invert(&a, &d, &m);
      ssh_bpoly_set(&d, &a);
    }

  check_timing(&tmit);

  printf("Inversions took %.8f seconds (on average).\n", tmit.real_secs / i);

#endif
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
  ssh_bpoly_clear(&d);
  ssh_bpoly_clear(&m);
}
#if 0
void find_small_irreducible()
{
  unsigned int i, j, prev;
  SshBPoly a, b, c;

  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  
  for (i = 1, j = 0, prev = 0; i < 10000; i++)
    {
      ssh_bpoly_set_ui(&a, i);
      if (ssh_bpoly_is_irreducible(&a) == TRUE)
        {
          if (prev)
            printf(", ");

          if (j++ > 3)
            {
              printf("\n");
              j = 0;
            }
          ssh_bpoly_pretty_print(&a);
          prev = 1;
        }
    }
  printf("\n");
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
}
#endif

#if 0
unsigned int log_size = 0;
unsigned int *alog = NULL;
unsigned int *log  = NULL;

void compute_log_tables(SshBPoly *a, SshBPoly *b)
{
  unsigned int i, j;
  SshBPoly t;
  
  i = ssh_bpoly_deg(a) - 1;

  ssh_bpoly_init(&t);

  ssh_bpoly_set(&t, b);

  log_size = (1 << i) - 1;
  alog = ssh_xmalloc(sizeof(unsigned int) * log_size);
  log  = ssh_xmalloc(sizeof(unsigned int) * log_size);

  log[0] = 1;
  alog[1] = 0;
  
  for (j = 1; j  < (1 << i); j++)
    {
      if (ssh_bpoly_cmp_ui(&t, 1) == 0)
        {
          printf("Error! Not a primitive element! Order %d.\n", j);
          break;
        }

      k = ssh_bpoly_get_ui(&t);
      log[j] = k;
      alog[k] = j;
      
      ssh_bpoly_mul(&t, &t, b);
      ssh_bpoly_mod(&t, &t, a);
    }

  ssh_bpoly_clear(&t);
}
#endif

void primitive_table(SshBPoly *a, SshBPoly *b)
{
  unsigned int i, j;
  SshBPoly t;
  
  i = ssh_bpoly_deg(a) - 1;

  ssh_bpoly_init(&t);

  ssh_bpoly_set(&t, b);
  
  for (j = 2; j  < ((1 << i) - 1); j++)
    {
      ssh_bpoly_mul(&t, &t, b);
      ssh_bpoly_mod(&t, &t, a);

      if (ssh_bpoly_cmp_ui(&t, 1) == 0)
        {
          printf("Error! Not a primitive element! Order %d.\n", j);
          break;
        }
    }

  ssh_bpoly_clear(&t);
}

void find_ip(unsigned int size)
{
  unsigned int i, j, prev;
  SshBPoly a, b, c;

  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  
  for (i = 1; i < (1 << size); i++)
    {
      ssh_bpoly_set_ui(&a, i | (1 << size));
      if (ssh_bpoly_is_irreducible(&a) == TRUE)
        {
          printf("Irreducible polynomial: ");
          ssh_bpoly_pretty_print(&a);
          printf("\n");

          for (j = 1, prev = 0; j < (1 << size); j++)
            {
              ssh_bpoly_set_ui(&b, j);
              if (ssh_bpoly_is_primitive(&b, &a) == TRUE)
                {
                  if (!prev)
                    printf("  Primitive element(s): \n");
                  printf("  ");
                  ssh_bpoly_pretty_print(&b);
                  printf("\n");
                  prev = 1;

#if 0
                  primitive_table(&a, &b);
#endif
                }
            }
          if (!prev)
            printf("  No primitive elements found.\n");
        }
    }
  printf("\n");
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
}

unsigned int find_small_irreducible(unsigned int size)
{
  unsigned int i, p;
  SshBPoly a;

  ssh_bpoly_init(&a);
  
  for (i = 1; i < (1 << size); i++)
    {
      ssh_bpoly_set_ui(&a, i | (1 << size));
      if (ssh_bpoly_is_irreducible(&a) == TRUE)
        {
          p = ssh_bpoly_get_ui(&a);
          ssh_bpoly_clear(&a);
          return p;
        }
    }
  ssh_bpoly_clear(&a);
  return 0;
}

unsigned int find_irreducible_trinomial(unsigned int size,
                                        unsigned int *n0, unsigned int *n1)
{
  unsigned int b0, b1;
  SshBPoly a;

  ssh_bpoly_init(&a);
  b1 = size;
  
  for (b0 = size/2 + 1; b0; b0--)
    {
      ssh_bpoly_set_ui(&a, 0);
      ssh_bpoly_set_bit(&a, 0);
      ssh_bpoly_set_bit(&a, b0);
      ssh_bpoly_set_bit(&a, b1);
      if (ssh_bpoly_is_irreducible(&a) == TRUE)
        {
          ssh_bpoly_clear(&a);
          *n0 = b0;
          *n1 = b1;
          return 1;
        }
    }
  ssh_bpoly_clear(&a);
  return 0;
}

int find_irreducible(int size, int *bits, int bits_count)
{
  int i, j;
  SshBPoly m;

  ssh_bpoly_init(&m);

  switch (bits_count)
    {
#if 0
    case 0:
    case 1:
    case 2:
    case 3:
      /* Search first for trinomials. */
      bits[0] = 0;
      bits[2] = size;
      for (bits[1] = bits[0] + 1; bits[1] < bits[2] - 32; bits[1]++)
        {
          ssh_bpoly_set_ui(&m, 0);
          ssh_bpoly_set_bit(&m, bits[0]);
          ssh_bpoly_set_bit(&m, bits[1]);
          ssh_bpoly_set_bit(&m, bits[2]);
          if (ssh_bpoly_is_irreducible(&m) == TRUE)
            {
              printf("  Irreducible: ");
              ssh_bpoly_pretty_print(&m);
              printf("\n");
              ssh_bpoly_clear(&m);
              return 1;
            }
        }
      ssh_bpoly_clear(&m);
      return 0;
      break;
    case 4:
    case 5:
      /* Then for pentanomials. */
      bits[0] = 0;
      bits[4] = size;
      bits[1] = 1;
      bits[2] = 2;
      for (bits[3] = 3; bits[3] < bits[4] - 32; bits[3]++)
        for (bits[2] = 2; bits[2] < bits[3] - 1; bits[2]++)
          for (bits[1] = 1; bits[1] < bits[2] - 1; bits[1]++)
            {
              ssh_bpoly_set_ui(&m, 0);
              ssh_bpoly_set_bit(&m, bits[0]);
              ssh_bpoly_set_bit(&m, bits[1]);
              ssh_bpoly_set_bit(&m, bits[2]);
              ssh_bpoly_set_bit(&m, bits[3]);
              ssh_bpoly_set_bit(&m, bits[4]);
              if (ssh_bpoly_is_irreducible(&m) == TRUE)
                {
                  printf("  Irreducible: ");
                  ssh_bpoly_pretty_print(&m);
                  printf("\n");
                  ssh_bpoly_clear(&m);
                  return 1;
                }
            }
      ssh_bpoly_clear(&m);
      return 0;
      break;
#endif
    default:
      if ((bits_count % 2) == 0)
        {
          ssh_bpoly_clear(&m);
          return 0;
        }

      bits[0] = 0;
      bits[bits_count - 1] = size;
      for (i = 1; i < bits_count - 1; i++)
        bits[i] = i;
      
      while (1)
        {
          ssh_bpoly_set_ui(&m, 0);
          for (i = 0; i < bits_count; i++)
            ssh_bpoly_set_bit(&m, bits[i]);
          if (ssh_bpoly_is_irreducible(&m) == TRUE)
            {
              if ((random() % 2) == 0)
                {
                  printf("  Irreducible: ");
                  ssh_bpoly_pretty_print(&m);
                  printf("\n");
                  break;
                }
            }
          
          for (i = 1; i < bits_count - 1; i++)
            if (bits[i] + 1 < bits[i + 1])
              {
                for (j = 1; j < i; j++)
                  bits[j] = j;
                bits[i]++;
                break;
              }
          if (i >= bits_count - 1)
            {
              ssh_bpoly_clear(&m);
              return 0;
            }
        }
      break;
    }
  ssh_bpoly_clear(&m);
  return 1;
}


/* Some elliptic curve tests. Using this generic gf(2^n), which means that
   computations are not fast, but they are probably good enough for
   testing. */

/* Classical binary transform vector (in fact this is pretty stupid
   in a sense). */
unsigned int transform_binary(const SshInt *k, char **transform_table)
{
  unsigned int maxbit, bit, scanbit, end, transform_index;
  char *transform;
  
  /* Seek the maximum number of bits. */

  maxbit = ssh_mp_get_size(k, 2);

  /* Set up scanning. */
  
  bit = 0;
  scanbit = 1;
  end = 0;
  transform_index = 0;

  transform = ssh_xmalloc(maxbit + 3);

  while (!end)
    {
      scanbit = ssh_mp_scan1(k, bit);
      if (scanbit >= maxbit)
        break;

      while (bit < scanbit)
        {
          transform[transform_index++] = 0;
          bit++;
        }

      scanbit = ssh_mp_scan0(k, bit);
      if (scanbit >= maxbit)
        end = 1;
      
      while (bit < scanbit)
        {
          transform[transform_index++] = 1;
          bit++;
        }
    }

  /* Return with transform index and table. */
  *transform_table = transform;
  return transform_index;
}

/* Computation of signed bit representation as in Morain & Olivos. */

unsigned int transform_mo(const SshInt *k, char **transform_table)
{
  unsigned int maxbit, bit, scanbit, b, end, transform_index;
  char *transform;
  
  /* Seek the maximum number of bits. */

  maxbit = ssh_mp_get_size(k, 2);

  /* Set up scanning. */
  
  bit = 0;
  scanbit = 1;
  b = 0;
  end = 0;
  transform_index = 0;

  /* Allocate and compute transform bit table.
     As suggested by Morain & Olivos. (This is equal to the P1363 method.)
     */

  transform = ssh_xmalloc(maxbit + 3);
  
  while (!end)
    {
      scanbit = ssh_mp_scan1(k, bit);
      if (scanbit >= maxbit)
        break;

      while (bit < scanbit)
        {
          if (b == 11)
            {
              b = 1;
            }
          else
            {
              if (b == 1)
                {
                  transform[transform_index++] = 1;
                  b = 0;
                }
              transform[transform_index++] = 0;
            }
          bit++;          
        }

      scanbit = ssh_mp_scan0(k, bit);
      if (scanbit >= maxbit)
        {
          scanbit = maxbit;
          end = 1;
        }

      while (bit < scanbit)
        {
          if (b == 0)
            {
              b = 1;
            }
          else
            {
              if (b == 1)
                {
                  transform[transform_index++] = -1; 
                  b = 11;
                }
              transform[transform_index++] = 0;
            }
          bit++;
        }
    }

  /* Set the highest bit. */
  transform[transform_index] = 1;

  /* Return with transform index and table. */
  *transform_table = transform;
  return transform_index + 1;
}

typedef struct
{
  SshBPoly x, y;
  int z;
} EC2nPoint;

typedef struct
{
  SshBPoly a, b, q;
  SshInt c;

  int f_c;
  unsigned int f_q, f_k, f_n, f_a, f_b;
} EC2nCurve;

void ec2n_init_point(EC2nPoint *P, EC2nCurve *E)
{
  ssh_bpoly_init(&P->x);
  ssh_bpoly_init(&P->y);
  P->z = 0;
}

void ec2n_clear_point(EC2nPoint *P)
{
  ssh_bpoly_clear(&P->x);
  ssh_bpoly_clear(&P->y);
  P->z = 0;
}

void ec2n_copy_point(EC2nPoint *P, EC2nPoint *Q)
{
  ssh_bpoly_set(&P->x, &Q->x);
  ssh_bpoly_set(&P->y, &Q->y);
  P->z = Q->z;
}

void ec2n_negate_point(EC2nPoint *Q, EC2nPoint *P)
{
  if (P->z == 0)
    return;
  
  if (Q != P)
    {
      ssh_bpoly_set(&Q->x, &P->x);
      ssh_bpoly_add(&Q->y, &P->y, &P->x);
      Q->z = P->z;
    }
  else
    ssh_bpoly_add(&Q->y, &Q->y, &Q->x);
}

void ec2n_init_curve(EC2nCurve *E)
{
  ssh_bpoly_init(&E->a);
  ssh_bpoly_init(&E->b);
  ssh_bpoly_init(&E->q);
  ssh_mp_init(&E->c);
  E->f_c = 0;
  E->f_q = 0;
  E->f_k = 0;
  E->f_n = 0;
  E->f_a = 0;
  E->f_b = 0;
}

void ec2n_clear_curve(EC2nCurve *E)
{
  ssh_bpoly_clear(&E->a);
  ssh_bpoly_clear(&E->b);
  ssh_bpoly_clear(&E->q);
  ssh_mp_clear(&E->c);
  E->f_q = 0;
  E->f_c = 0;
  E->f_k = 0;
  E->f_n = 0;
  E->f_a = 0;
  E->f_b = 0;
}

void ec2n_copy_curve(EC2nCurve *E, EC2nCurve *C)
{
  ssh_bpoly_set(&E->a, &C->a);
  ssh_bpoly_set(&E->b, &C->b);
  ssh_bpoly_set(&E->q, &C->q);
  ssh_mp_set(&E->c, &C->c);
  E->f_q = C->f_q;
  E->f_c = C->f_c;
  E->f_k = C->f_k;
  E->f_n = C->f_n;
  E->f_a = C->f_a;
  E->f_b = C->f_b;
}

int ec2n_check_values(EC2nPoint *P, EC2nCurve *E)
{
  SshBPoly x, y, t;
  int rv = 1;

  ssh_bpoly_init(&x);
  ssh_bpoly_init(&y);
  ssh_bpoly_init(&t);

  /* x^2 */
  ssh_bpoly_square(&x, &P->x);
  ssh_bpoly_mod(&x, &x, &E->q);

  /* y^2 */
  ssh_bpoly_square(&y, &P->y);
  ssh_bpoly_mod(&y, &y, &E->q);

  /* x*y */
  ssh_bpoly_mul(&t, &P->x, &P->y);
  ssh_bpoly_mod(&t, &t, &E->q);

  /* y^2 + xy */
  ssh_bpoly_add(&y, &y, &t);

  /* x^3 */
  ssh_bpoly_mul(&t, &x, &P->x);
  ssh_bpoly_mod(&t, &t, &E->q);

  /* y - x^3 */
  ssh_bpoly_add(&y, &y, &t);

  /* a*x^2 */
  ssh_bpoly_mul(&t, &x, &E->a);
  ssh_bpoly_mod(&t, &t, &E->q);

  /* y - ax^2 */
  ssh_bpoly_add(&y, &y, &t);

  /* y - b */
  ssh_bpoly_add(&y, &y, &E->b);

  if (ssh_bpoly_cmp_ui(&y, 0) != 0)
    rv = 0;
  
  ssh_bpoly_clear(&x);
  ssh_bpoly_clear(&y);
  ssh_bpoly_clear(&t);
  return rv;
}

/* Brute force computation of the order of very small elliptic
   curve. */

unsigned int ec2n_small_curve(unsigned int iq, unsigned int ia,
                              unsigned int ib, unsigned int n)
{

  SshBPoly a, b, q, x, t1, t2, trace;
  unsigned int i, c, trace_a;

  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&q);
  ssh_bpoly_init(&x);
  ssh_bpoly_init(&t1);  
  ssh_bpoly_init(&t2);
  ssh_bpoly_init(&trace);

  /* Set it up. */
  ssh_bpoly_set_ui(&q, iq);
  ssh_bpoly_set_ui(&a, ia);
  ssh_bpoly_set_ui(&b, ib);
  
  /* The curve is:

     y^2 + xy = x^3 + ax^2 + b,

     thus

     (y/x)^2 + (y/x) = x + a + (b/x^2).

     We know that for

     z^2 + z = b, there exist a solution in z only if
     Tr(b) = 0. Thus we should compute

     Tr(x + a + (b/x^2)) and see whether it is zero or not.

     Also it is easily seen that

     Tr(x + a + (b/x^2)) = Tr(a) + Tr(x + (b/x^2)).

     The number of points in E is

     (0, sqrt{b}) + point at infinity +

     all such x for which Tr(x + a + (b/x^2)) = 0. 

     */

  ssh_bpoly_trace(&trace, &a, &q);
  if (ssh_bpoly_cmp_ui(&trace, 0) == 0)
    trace_a = 0;
  else
    trace_a = 1;
  
  for (i = 1, c = 0; i < (1 << n); i++)
    {
      /* Compute: x + b/x^2 */
      ssh_bpoly_set_ui(&x, i);
      ssh_bpoly_square(&t1, &x);
      ssh_bpoly_mod(&t1, &t1, &q);
      ssh_bpoly_invert(&t2, &t1, &q);
      ssh_bpoly_mul(&t2, &b, &t2);
      ssh_bpoly_mod(&t2, &t2, &q);
      ssh_bpoly_add(&t2, &t2, &x);

      /* Compute trace. */
      ssh_bpoly_trace(&trace, &t2, &q);
      if (ssh_bpoly_cmp_ui(&trace, 0) == 0)
        c++;
      else
        c--;
    }

  if (trace_a == 1)
    c = -c;
  c += 1 + (1 << n);
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&q);
  ssh_bpoly_clear(&x);
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t2);
  ssh_bpoly_clear(&trace);
  
  return c;
}

/* This tries to find with trial division a large divisor of composite. */
void factor(SshInt *large, const SshInt *composite)
{
  SshSieve sieve;
  unsigned long i;
  
  if (ssh_mp_is_probable_prime(composite, 25))
    {
      ssh_mp_set(large, composite);
      return;
    }

  ssh_mp_set(large, composite);
  
  ssh_sieve_allocate(&sieve, 100000);
  for (i = 2; i; i = ssh_sieve_next_prime(i, &sieve))
    {
      while (ssh_mp_mod_ui(large, i) == 0)
        ssh_mp_div_ui(large, large, i);
          
    }
  ssh_sieve_free(&sieve);
  if (ssh_mp_is_probable_prime(large, 25))
    return;

  printf("warning: did not find a large probable prime with trial division.\n");
}

void ec2n_expand_trace(SshInt *card, int c, unsigned int n,
                       unsigned int k)
{
  SshInt c1, c2, t1, t2;
  int i;

  /* Compute trivially with Lucas sequence. */

  ssh_mp_init(&c1);
  ssh_mp_init(&c2);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);

  ssh_mp_set_si(card, c);
  ssh_mp_set_ui(&c1, 2);
  ssh_mp_set(&c2, card);
  
  for (i = 2; i <= k; i++)
    {
      ssh_mp_mul(&t1, &c2, card);
      ssh_mp_mul_ui(&t2, &c1, (1 << n));
      ssh_mp_set(&c1, &c2);
      ssh_mp_sub(&c2, &t1, &t2);
    }

  printf("  trace ");
  ssh_mp_out_str(NULL, 10, &c2);
  printf("\n");

  printf(" Checking which way we could get large prime order points.\n");
  
  /* Compute the cardinality of the resultant curve. */
  ssh_mp_set_ui(card, 1);
  ssh_mp_mul_2exp(card, card, k*n);
  ssh_mp_add_ui(card, card, 1);
  ssh_mp_sub(card, card, &c2);

  factor(&c1, card);
  printf("  2^q - t -> ");
  ssh_mp_out_str(NULL, 10, &c1);
  printf("\n");
  
  ssh_mp_clear(&c1); 
  ssh_mp_clear(&c2);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2); 
}

void ec2n_find_point(EC2nPoint *P, EC2nCurve *E)
{
  SshBPoly t1, t2, t3, t4;

  ssh_bpoly_init(&t1);
  ssh_bpoly_init(&t2);
  ssh_bpoly_init(&t3);
  ssh_bpoly_init(&t4);
  
  while (1)
    {
      /* Find random number */
      /*ssh_bpoly_poor_rand(&P->x, &E->q);*/
      ssh_bpoly_set_ui(&P->x, random());

      if (ssh_bpoly_cmp_ui(&P->x, 0) == 0)
        {
          ssh_bpoly_powm_2exp(&P->y, &E->b, ssh_bpoly_deg(&E->q) - 1, &E->q);
          break;
        }

      ssh_bpoly_square(&t1, &P->x);
      ssh_bpoly_mod(&t1, &t1, &E->q);
      
      ssh_bpoly_mul(&t2, &t1, &P->x);
      ssh_bpoly_mul(&t3, &t1, &E->a);
      ssh_bpoly_add(&t2, &t2,  &t3);
      ssh_bpoly_mod(&t2, &t2, &E->q);

      ssh_bpoly_add(&t2, &t2, &E->b);

      if (ssh_bpoly_cmp_ui(&t2, 0) == 0)
        {
          ssh_bpoly_set_ui(&P->y, 0);
          break;
        }

      ssh_bpoly_invert(&t1, &P->x, &E->q);
      ssh_bpoly_square(&t3, &t1);
      ssh_bpoly_mod(&t3, &t3, &E->q);

      ssh_bpoly_mul(&t4, &t3, &t2);
      ssh_bpoly_mod(&t4, &t4, &E->q);

      if (ssh_bpoly_quad_solve(&t1, &t4, &E->q) == TRUE)
        {
          ssh_bpoly_mul(&P->y, &P->x, &t1);
          ssh_bpoly_mod(&P->y, &P->y, &E->q);
          break;
        }
    }

  if (ec2n_check_values(P, E) == 0)
    {
      printf("For starters, everything is going mad!\n");
    }
  
  P->z = 1;
  
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t2);
  ssh_bpoly_clear(&t3);
  ssh_bpoly_clear(&t4);
}

typedef struct
{
  SshBPoly t1, t2, t3, t4;
} EC2nContext;

void ec2n_init_context(EC2nContext *ctx, EC2nCurve *E)
{
  ssh_bpoly_init(&ctx->t1);
  ssh_bpoly_init(&ctx->t2);
  ssh_bpoly_init(&ctx->t3);
  ssh_bpoly_init(&ctx->t4);
}

void ec2n_clear_context(EC2nContext *ctx)
{
  ssh_bpoly_clear(&ctx->t1);
  ssh_bpoly_clear(&ctx->t2);
  ssh_bpoly_clear(&ctx->t3);
  ssh_bpoly_clear(&ctx->t4);
}

void ec2n_internal_double(EC2nPoint *R, EC2nPoint *P, EC2nCurve *E,
                          EC2nContext *ctx)
{
  /* Doubling a point */
  ssh_bpoly_invert(&ctx->t1, &P->x, &E->q);
  ssh_bpoly_mul(&ctx->t2, &ctx->t1, &P->y);
  ssh_bpoly_mod(&ctx->t2, &ctx->t2, &E->q);
  ssh_bpoly_add(&ctx->t2, &ctx->t2, &P->x);
  
  /* t2 is now the lambda */
  ssh_bpoly_square(&ctx->t1, &ctx->t2);
  ssh_bpoly_mod(&ctx->t1, &ctx->t1, &E->q);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &ctx->t2);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &E->a);
  
  ssh_bpoly_square(&ctx->t3, &P->x);
  ssh_bpoly_mod(&ctx->t3, &ctx->t3, &E->q);
  ssh_bpoly_add_ui(&ctx->t2, &ctx->t2, 1);
  ssh_bpoly_mul(&ctx->t4, &ctx->t2, &ctx->t1);
  ssh_bpoly_mod(&ctx->t4, &ctx->t4, &E->q);
  ssh_bpoly_add(&ctx->t3, &ctx->t3, &ctx->t4);
  
  /* Output */
  ssh_bpoly_set(&R->x, &ctx->t1);
  ssh_bpoly_set(&R->y, &ctx->t3);
  R->z = 1;
}  

void ec2n_internal_add(EC2nPoint *R, EC2nPoint *P, EC2nPoint *Q, EC2nCurve *E,
                       EC2nContext *ctx)
{

  /* Compute lambda */
  ssh_bpoly_add(&ctx->t1, &P->x, &Q->x);
  ssh_bpoly_invert(&ctx->t2, &ctx->t1, &E->q);

  ssh_bpoly_add(&ctx->t1, &P->y, &Q->y);
  ssh_bpoly_mul(&ctx->t3, &ctx->t1, &ctx->t2);
  ssh_bpoly_mod(&ctx->t3, &ctx->t3, &E->q);

  /* Compute x */
  ssh_bpoly_square(&ctx->t1, &ctx->t3);
  ssh_bpoly_mod(&ctx->t1, &ctx->t1, &E->q);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &ctx->t3);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &P->x);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &Q->x);
  ssh_bpoly_add(&ctx->t1, &ctx->t1, &E->a);

  /* Compute y */
  ssh_bpoly_add(&ctx->t2, &P->x, &ctx->t1);
  ssh_bpoly_mul(&ctx->t4, &ctx->t2, &ctx->t3);
  ssh_bpoly_mod(&ctx->t4, &ctx->t4, &E->q);
  ssh_bpoly_add(&ctx->t4, &ctx->t4, &ctx->t1);
  ssh_bpoly_add(&ctx->t4, &ctx->t4, &P->y);

  /* Set for output */
  ssh_bpoly_set(&R->x, &ctx->t1);
  ssh_bpoly_set(&R->y, &ctx->t4);
  R->z = 1;
}
     
void ec2n_generic_add(EC2nPoint *R, EC2nPoint *P, EC2nPoint *Q, EC2nCurve *E,
                      EC2nContext *ctx)
{
  if (P->z == 0)
    {
      ssh_bpoly_set(&R->x, &Q->x);
      ssh_bpoly_set(&R->y, &Q->y);
      R->z = Q->z;
      return;
    }
  if (Q->z == 0)
    {
      ssh_bpoly_set(&R->x, &P->x);
      ssh_bpoly_set(&R->y, &P->y);
      R->z = P->z;
      return;
    }

  if (ssh_bpoly_cmp(&P->x, &Q->x) == 0)
    {
      if (ssh_bpoly_cmp(&P->y, &Q->y) != 0 || ssh_bpoly_cmp_ui(&P->x, 0) == 0)
        {
          R->z = 0;
          return;
        }

      ec2n_internal_double(R, P, E, ctx);
      return;
    }
  
  ec2n_internal_add(R, P, Q, E, ctx);
}
     
void ec2n_add(EC2nPoint *R, EC2nPoint *P, EC2nPoint *Q, EC2nCurve *E)
{
  EC2nContext ctx;
  ec2n_init_context(&ctx, E);
  ec2n_generic_add(R, P, Q, E, &ctx);
  ec2n_clear_context(&ctx);
}


/* Generic multiplication. But then again, with GF(2^n) one can probably
   live with just the generic one? */
void ec2n_mul(EC2nPoint *R, EC2nPoint *P, SshInt *k,
              EC2nCurve *E)
{
  EC2nContext ctx;
  EC2nPoint T, H, I;
  char *transform;
  int i;

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      R->z = 0;
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ec2n_copy_point(R, P);
      return;
    }

  /* Initialize. */
  ec2n_init_point(&T, E);
  ec2n_init_point(&H, E);
  ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ec2n_init_context(&ctx, E);

  /* Transform scalar multiplier to a signed representation. */
  i = transform_mo(k, &transform) - 1;

  /* Set temporary projective points. */
  ec2n_copy_point(&H, P);
  ec2n_copy_point(&T, P);
  ec2n_negate_point(&I, &H);

  /* Multiply using transform bit-vector. */
  
  for (; i; i--)
    {
      ec2n_generic_add(&T, &T, &T, E, &ctx);
      if (transform[i - 1])
        {
          if (transform[i - 1] == -1)
            ec2n_generic_add(&T, &T, &I, E, &ctx);
          else
            ec2n_generic_add(&T, &T, &H, E, &ctx);
        }
    }

  ec2n_copy_point(R, &T);

  /* Clear temporary space. */

  ssh_xfree(transform);
  
  ec2n_clear_point(&T);
  ec2n_clear_point(&H);
  ec2n_clear_point(&I);
  ec2n_clear_context(&ctx);
}

/* This works only for curves defined also over small field.
   (Actually Frobenius endomorphism works for all, but this code
    fragment assumes E->f_q set, thus doesn't work correctly
    otherwise.) */
void ec2n_frobenius(EC2nPoint *R, EC2nPoint *P, EC2nCurve *E)
{
  unsigned int i;
  if (P->z == 0)
    {
      R->z = 0;
      return;
    }
  if (R != P)
    ec2n_copy_point(R, P);
  for (i = 0; i < E->f_q; i++)
    {
      ssh_bpoly_square(&R->x, &R->x);
      ssh_bpoly_mod(&R->x, &R->x, &E->q);
      ssh_bpoly_square(&R->y, &R->y);
      ssh_bpoly_mod(&R->y, &R->y, &E->q);
    }
}

/* Frobenius multiplication as given by Volker Mueller. */
void ec2n_mul_frobenius(EC2nPoint *R, EC2nPoint *P, SshInt *k,
                        EC2nCurve *E)
{
  EC2nContext ctx;
  EC2nPoint T, I;
  EC2nPoint *F;
  SshInt n, h, s1, s2;
  unsigned int q;
  int *r;
  int i, t;

  ssh_mp_init(&n);
  /* First reduce to suitable residue, just in case. */
  ssh_mp_mod(&n, k, &E->c);

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(&n, 0) == 0)
    {
      R->z = 0;
      ssh_mp_clear(&n);
      return;
    }
  if (ssh_mp_cmp_ui(&n, 1) == 0)
    {
      ec2n_copy_point(R, P);
      ssh_mp_clear(&n);
      return;
    }

  /* Initialize. */
  ec2n_init_point(&T, E);
  ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ec2n_init_context(&ctx, E);

  /* printf("nP table initialization.\n"); */
  
  /* Compute large enough table. */
  q = (1 << E->f_q);
  F = ssh_xmalloc(sizeof(EC2nPoint) * (q/2 + 1));
  ec2n_init_point(&F[0], E);
  ec2n_init_point(&F[1], E);
  ec2n_copy_point(&F[1], P);
  for (i = 2; i <= q/2; i++)
    {
      ec2n_init_point(&F[i], E);
      ec2n_generic_add(&F[i], &F[i - 1], P, E, &ctx);
    }

  /* Build Frobenius represenation of the exponent. */
  ssh_mp_init(&s1);
  ssh_mp_init(&s2);
  ssh_mp_init(&h);

  ssh_mp_set(&s1, &n);
  ssh_mp_set_ui(&s2, 0);

  /*printf("Building the Frobenius table.\n");*/
  
  r = ssh_xmalloc(sizeof(int) * (ssh_mp_get_size(&n,2) + 10));
  i = 0;
  while (1)
    {
      /*printf(" s1 = ");
      ssh_mp_out_str(NULL, 10, &s1);
      printf("\n");
      printf(" s2 = ");
      ssh_mp_out_str(NULL, 10, &s2);
      printf("\n");*/
      
      ssh_mp_abs(&n, &s1);
      ssh_mp_abs(&h, &s2);
      if (ssh_mp_cmp_ui(&n, q/2) <= 0 && 
          ssh_mp_cmp_ui(&h, 1) <= 0)
        break;

      ssh_mp_mod_2exp(&n, &s1, E->f_q);
      /*printf(" n = ");
      ssh_mp_out_str(NULL, 10, &n);
      printf("\n"); */
      if (ssh_mp_cmp_ui(&n, 0) < 0)
        ssh_mp_add_ui(&n, &n, q);
      r[i] = ssh_mp_get_si(&n);
      /*printf(" r[%d] = %d\n", i, r[i]); */
      if (r[i] > (int)q/2)
        r[i] -= (int)q;

      ssh_mp_set_si(&n, r[i]);
      /*printf(" n = ");
      ssh_mp_out_str(NULL, 10, &n);
      printf("\n");*/
      ssh_mp_sub(&n, &n, &s1);
      /*printf(" n = ");
      ssh_mp_out_str(NULL, 10, &n);
      printf("\n");*/
      ssh_mp_div_2exp(&n, &n, E->f_q);
      /*printf(" n = ");
      ssh_mp_out_str(NULL, 10, &n);
      printf("\n");*/

      ssh_mp_set_si(&h, E->f_c);
      /*printf(" h = ");
      ssh_mp_out_str(NULL, 10, &h);
      printf("\n");*/
      ssh_mp_mul(&h, &h, &n);
      /*printf(" h = ");
      ssh_mp_out_str(NULL, 10, &h);
      printf("\n");*/
      ssh_mp_sub(&s1, &s2, &h);
      ssh_mp_set(&s2, &n);
      /* printf(" %d, ", r[i]); */
      i++;
    }
  /* printf(" --\n");
  printf("Adding things up.\n"); */

  /* Set the T. */
  t = ssh_mp_get_si(&s1);
  if (t != 0)
    {
      if (t < 0)
        ec2n_negate_point(&T, &F[-t]);
      else
        ec2n_copy_point(&T, &F[t]);
    }
  t = ssh_mp_get_si(&s2);
  if (t != 0)
    {
      ec2n_frobenius(&I, P, E);
      if (t < 0)
        ec2n_negate_point(&I, &I);
      ec2n_generic_add(&T, &T, &I, E, &ctx);
    }
    
  /* Multiply using Frobenius transform vector. */
  
  for (; i; i--)
    {
      /* printf(".");
      fflush(stdout); */
      
      ec2n_frobenius(&T, &T, E);
      t = r[i - 1];
      if (t < 0)
        {
          ec2n_negate_point(&I, &F[-t]);
          ec2n_generic_add(&T, &T, &I, E, &ctx);
        }
      else
        ec2n_generic_add(&T, &T, &F[t], E, &ctx);
    }
  /* printf("\n"); */
  
  ec2n_copy_point(R, &T);

  /* Clear temporary space. */

  ssh_mp_clear(&s1);
  ssh_mp_clear(&s2);
  ssh_mp_clear(&h);
  ssh_mp_clear(&n);
  
  ssh_xfree(r);
  for (i = 0; i <= q/2; i++)
    ec2n_clear_point(&F[i]);
  ssh_xfree(F);
  
  ec2n_clear_point(&T);
  ec2n_clear_point(&I);
  ec2n_clear_context(&ctx);
}

void ec2n_find_point_of_order(EC2nPoint *P, SshInt *n, EC2nCurve *E)
{
  SshInt k;
  EC2nPoint R;
  
  ssh_mp_init(&k);
  ssh_mp_div_q(&k, &E->c, n);
  printf(" k = ");
  ssh_mp_out_str(NULL, 10, &k);
  printf("\n");
  
  ec2n_init_point(&R, E);
  
  while (1)
    {
      ec2n_find_point(&R, E);
      ec2n_mul(P, &R, &k, E);
      if (P->z != 0)
        break;
    }
  ec2n_mul(&R, P, n, E);
  if (R.z != 0)
    ssh_fatal("error: could not find point of selected order.");

  ec2n_clear_point(&R);
  ssh_mp_clear(&k);
}

#if 1
/* This needs some reworking because of the SshGF2nPoly routines are
   not yet tests. */

/* This routine uses some polynomial routines. It might fail badly :) */
int ec2n_extension_embedding(SshBPoly *r1, SshBPoly *r2,
                             SshBPoly *e1, SshBPoly *e2,
                             SshBPoly * p, SshBPoly * m)
{
  SshGF2nPoly f, c, h, t;
  SshGF2nModuli gfm;
  SshGF2nElement gf_lambda, gfu;
  SshBPoly u, v, tv, lambda;
  unsigned int i;
  int rv = 1;
  
  /* First translate the p -> f(x). */
  ssh_gf2n_init_mod_bpoly(&gfm, m);
  ssh_gf2n_poly_init(&f, &gfm);
  for (i = 0; i < ssh_bpoly_deg(p); i++)
    if (ssh_bpoly_get_bit(p, i))
      ssh_gf2n_poly_setall(&f, SSH_GF2N_POLY_UI, i, 1, SSH_GF2N_POLY_END);

  /* Initialize some variables. */
  ssh_bpoly_init(&u);
  ssh_gf2n_poly_init(&c, &gfm);
  ssh_gf2n_poly_init(&h, &gfm);
  ssh_gf2n_poly_init(&t, &gfm);

  for (; ssh_gf2n_poly_deg(&f) > 2; )
    {
      /* Set c(x) = ux, where u is random. */
      ssh_bpoly_poor_rand(&u, m);
      /*ssh_bpoly_set_ui(&u,0x429f3b81); */
      ssh_gf2n_poly_set_zero(&c);
      ssh_gf2n_poly_setall(&c, SSH_GF2N_POLY_BPOLY, 1, &u, SSH_GF2N_POLY_END);
      ssh_gf2n_poly_set(&h, &c);

      /* Do a bit of looping. */
      for (i = 1; i < ssh_bpoly_deg(m) - 1; i++)
        {
          ssh_gf2n_poly_square(&t, &c);
          /*printf(" t = ");
          ssh_gf2n_poly_print(&t); 
          printf("\n"); */
          ssh_gf2n_poly_mod(&c, &t, &f);
          /*printf(" c = ");
          ssh_gf2n_poly_print(&c);
          printf("\n"); */
          ssh_gf2n_poly_add(&c, &h);
          /*printf(" c = ");
          ssh_gf2n_poly_print(&c);
          printf("\n"); */
        }

      /* Do some gcd computations. */
      ssh_gf2n_poly_gcd(&h, &c, &f);

      /*
      printf(" h = ");
      ssh_gf2n_poly_print(&h);
      printf("\n");

      printf(" c = ");
      ssh_gf2n_poly_print(&c);
      printf("\n");

      printf(" f = ");
      ssh_gf2n_poly_print(&f);
      printf("\n");
      */

      if (ssh_gf2n_poly_deg(&h) <= 1 ||
          ssh_gf2n_poly_deg(&h) == ssh_gf2n_poly_deg(&f))
        continue;

      if (2*(ssh_gf2n_poly_deg(&h) - 1) > (ssh_gf2n_poly_deg(&f) - 1))
        {
          ssh_gf2n_poly_div(&t, &c, &f, &h);
          ssh_gf2n_poly_set(&f, &t);
          /* printf("div\n"); */
        }
      else
        ssh_gf2n_poly_set(&f, &h);

      /*
      printf(" f = ");
      ssh_gf2n_poly_print(&f);
      printf("\n");

      ssh_gf2n_poly_mul(&t, &f, &h);
      printf(" f*h = ");
      ssh_gf2n_poly_print(&t);
      printf("\n");
      
      printf(" c = ");
      ssh_gf2n_poly_print(&c);
      printf("\n");
      */
    }

  /* Make the polynomial as monic, because this ensures that the
     root is unique. */
  ssh_gf2n_poly_monic(&f);
  
  /* Get the constant. */
  ssh_gf2n_init(&gf_lambda, &gfm);
  ssh_gf2n_poly_getall(&f, SSH_GF2N_POLY_GF2N, 0,
                       &gf_lambda, SSH_GF2N_POLY_END);

  /* Verify that the root is really from correct polynomial. */
  ssh_gf2n_poly_set_zero(&h);
  for (i = 0; i < ssh_bpoly_deg(p); i++)
    if (ssh_bpoly_get_bit(p, i))
      ssh_gf2n_poly_setall(&h, SSH_GF2N_POLY_UI, i, 1, SSH_GF2N_POLY_END);

  ssh_gf2n_init(&gfu, &gfm);
  ssh_gf2n_poly_evaluate(&gfu, &h, &gf_lambda);
  ssh_bpoly_set_gf2n(&u, &gfu);
  ssh_gf2n_clear(&gfu);

  if (ssh_bpoly_cmp_ui(&u, 0) != 0)
    rv = 0;

  ssh_bpoly_init(&lambda);
  ssh_bpoly_set_gf2n(&lambda, &gf_lambda);
  ssh_gf2n_clear(&gf_lambda);

  /* Free some stuff. */
  ssh_gf2n_poly_clear(&f);
  ssh_gf2n_poly_clear(&c);
  ssh_gf2n_poly_clear(&h);
  ssh_gf2n_poly_clear(&t);

  ssh_gf2n_clear_mod(&gfm);
  
  ssh_bpoly_init(&v);
  ssh_bpoly_init(&tv);
    
  ssh_bpoly_set_ui(&u, 1);
  ssh_bpoly_set_ui(&v, 0);
  ssh_bpoly_set_ui(&tv, 0);
  
  for (i = 0; i < ssh_bpoly_deg(p) - 1; i++)
    {
      if (ssh_bpoly_get_bit(e1, i))
        ssh_bpoly_add(&v, &v, &u);
      if (ssh_bpoly_get_bit(e2, i))
        ssh_bpoly_add(&tv, &tv, &u);
      ssh_bpoly_mul(&u, &u, &lambda);
      ssh_bpoly_mod(&u, &u, m);
    }

  ssh_bpoly_set(r1, &v);
  ssh_bpoly_set(r2, &tv);

  ssh_bpoly_clear(&u);
  ssh_bpoly_clear(&v);
  ssh_bpoly_clear(&tv);
  
  ssh_bpoly_clear(&lambda);
  return rv;
}

/* Here will be magic of generating curve over f_q and over f_q^k. */
void ec2n_generate_curve(EC2nCurve *E, unsigned int n, unsigned int k,
                         int *bits, int bits_count)
{
  unsigned int a, b, q;
  SshBPoly p, x, y;
  int i;
  
  if (n == 0)
    {
      printf("What are you doing?\n");
      abort();
    }
  
  q = find_small_irreducible(n);
  if (q == 0)
    {
      printf("What happened?\n");
      abort();
    }

  ssh_bpoly_init(&p);
  ssh_bpoly_init(&x);
  ssh_bpoly_init(&y);

  ssh_bpoly_set_ui(&p, q);
  printf("Irreducible polynomial ");
  ssh_bpoly_pretty_print(&p);
  printf(" selected for GF(2^%u).\n", n);

#if 0
  printf("Testing: running through all small curves...\n");
  for (a = (random() % (1 << n)); a < (1 << n); a++)
    for (b = 1; b < (1 << n); b++)
      {
        printf(" a = %u b = %u\n", a, b);

        /* Compute the order (actually the trace) of the given curve. */
        E->f_q = n;
        E->f_c = (1 << n) + 1 - ec2n_small_curve(q, a, b, n);
        E->f_k = k;
        E->f_n = k * n;
        E->f_a = a;
        E->f_b = b;
        
        printf("Curve over GF(%u) has trace %d.\n", (1 << E->f_q), E->f_c);
        
        /* Now extend this trace to E(GF(2^(n*k))). */
        
        ec2n_expand_trace(&E->c, E->f_c, n, k);
      }
#endif
#if 1
  /* Now we'd like to compute the order of the elliptic curve
     over GF(2^n).
     */
  do
    {
      a = random() & ((1 << n) - 1);
      b = random() & ((1 << n) - 1);
    }
  while (b == 0);
#else
  a = 67; b = 25;
#endif
  
  printf("Curve parameters %u and %u selected.\n", a, b);
  
  /* Compute the order (actually the trace) of the given curve. */
  E->f_q = n;
  E->f_c = (1 << n) + 1 - ec2n_small_curve(q, a, b, n);
  E->f_k = k;
  E->f_n = k * n;
  E->f_a = a;
  E->f_b = b;
  
  printf("Curve over GF(%u) has trace %d.\n", (1 << E->f_q), E->f_c);
  
  /* Now extend this trace to E(GF(2^(n*k))). */

  ec2n_expand_trace(&E->c, E->f_c, n, k);
  
  /* Set the generic modulus. */
  for (i = 0; i < bits_count; i++)
    ssh_bpoly_set_bit(&E->q, bits[i]);

  printf("Curve should have the cardinality ");
  ssh_mp_out_str(NULL, 10, &E->c);
  printf("\n");
  printf("The field irreducible polynomial is \n");
  ssh_bpoly_pretty_print(&E->q);
  printf("\n");

  printf("Testing whether there exists a curve which satisfies this.\n");

  printf("Compute embeddings.\n");

  ssh_bpoly_set_ui(&x, a);
  ssh_bpoly_set_ui(&y, b);
  ec2n_extension_embedding(&E->a, &E->b, &x, &y, &p, &E->q);

#if 0

  /* If you which later to implement more efficient good curve search use
     this also. */
  {
    
    SshInt z;
    ssh_mp_init(&z);
    ssh_mp_set_ui(&z, 1);
    ssh_mp_mul_2exp(&z, ssh_bpoly_deg(&E->q));
    ssh_mp_add_ui(&z, 1);
    ssh_mp_sub(&E->c, &z, &E->c);
    ssh_mp_clear(&z);
  }
  
  /* Half of the elements in GF(2^n) has trace 0. */
  while (1)
    {
      /*ssh_bpoly_poor_rand(&t, &E->q); */
      ssh_bpoly_set_ui(&t, random());
      ssh_bpoly_trace(&x, &t, &E->q);
      if (ssh_bpoly_cmp_ui(&x, 1) == 0)
        break;
    }

  ssh_bpoly_add(&E->a, &E->a, &t);
#endif
  
  printf("Curve over GF(2^%u) is\n"
         "E: y^2 + xy = x^2 + ", E->f_n);
  ssh_bpoly_hex_dump(&E->a);
  printf("*x^2 + ");
  ssh_bpoly_hex_dump(&E->b);
  printf("\n");
  printf("Field irreducible trinomial is: \n");
  ssh_bpoly_hex_dump(&E->q);
  printf("\n");

  ssh_bpoly_clear(&x);
  ssh_bpoly_clear(&y);
  ssh_bpoly_clear(&p);
}

void test_ec2n(unsigned int n,
               int *bits, int bits_count)
{
  EC2nCurve E;
  EC2nPoint P, Q, R, T;
  unsigned int k = bits[bits_count - 1]/n, i, l /* ,j */;
  SshInt t, large;
  
  printf("Generating a curve y^2 + xy = x^3 + ax^2 + b in GF(2^(%u*%u))\n",
         n, k);

  ec2n_init_curve(&E);

  ec2n_generate_curve(&E, n, k, bits, bits_count);

  ssh_mp_init(&large);
  factor(&large, &E.c);
  printf(" large card factor: ");
  ssh_mp_out_str(NULL, 10, &large);
  printf("\n");
  
  ec2n_init_point(&P, &E);
  ec2n_init_point(&Q, &E);

  ec2n_find_point_of_order(&P, &large, &E);

  printf("Random point is \n { ");
  ssh_bpoly_hex_dump(&P.x);
  printf(", ");
  ssh_bpoly_hex_dump(&P.y);
  printf(", %u }\n", P.z);
  
  ec2n_mul(&Q, &P, &E.c, &E);

  printf("#E * P is \n { ");
  ssh_bpoly_hex_dump(&Q.x);
  printf(", ");
  ssh_bpoly_hex_dump(&Q.y);
  printf(", %u }\n", Q.z);
  
  if (Q.z != 0)
    printf("Error occurred.\n");

  ec2n_init_point(&R, &E);
  ec2n_init_point(&T, &E);
  ssh_mp_init(&t);

  printf("Frobenius multiplication test!\n");
  for (i = 0; i < 10; i++)
    {
      /* printf("Counter %u\n", i + 1); */
      l = random() % 10000000;
      /* printf(" exp = %u\n", l); */
      
      /* Compute with traditional simple methods. */
      /*ec2n_copy_point(&T, &P);
      for (j = 1; j < l; j++)
        ec2n_add(&T, &T, &P, &E); */

      /* printf("Computing %u*P.\n", l);*/
      ssh_mp_set_ui(&t, l);
      /* This multiplication should work. */
      ec2n_mul(&Q, &P, &t, &E);

      /*
      if ((T.z == 1 && Q.z == 1 && (ssh_bpoly_cmp(&T.x, &Q.x) != 0 ||
                                    ssh_bpoly_cmp(&T.y, &Q.y) != 0))
          || (T.z != Q.z))
        {
          printf("%u not exactly same (1).\n", i);
          printf("T = (");
          ssh_bpoly_hex_dump(&T.x);
          printf(", ");
          ssh_bpoly_hex_dump(&T.y);
          printf(")\n");
          printf("Q = (");
          ssh_bpoly_hex_dump(&Q.x);
          printf(", ");
          ssh_bpoly_hex_dump(&Q.y);
          printf(")\n");          
        }
        */
      
      /* This might not. */
      /* printf("Frobenius method.\n");*/
      ec2n_mul_frobenius(&R, &P, &t, &E);

      /* printf("Checking..\n"); */
      if ((R.z == 1 && Q.z == 1 && (ssh_bpoly_cmp(&R.x, &Q.x) != 0 ||
                                    ssh_bpoly_cmp(&R.y, &Q.y) != 0))
          || (R.z != Q.z))
        {
          printf("%u not exactly same (2).\n", i);
          printf("R = (");
          ssh_bpoly_hex_dump(&R.x);
          printf(", ");
          ssh_bpoly_hex_dump(&R.y);
          printf(")\n");
          printf("Q = (");
          ssh_bpoly_hex_dump(&Q.x);
          printf(", ");
          ssh_bpoly_hex_dump(&Q.y);
          printf(")\n");          
        }
    }
  
  ssh_mp_clear(&t);
  ssh_mp_clear(&large);
  
  ec2n_clear_point(&T);
  ec2n_clear_point(&R);
  ec2n_clear_point(&P);
  ec2n_clear_point(&Q);
  ec2n_clear_curve(&E);
}

#endif

void testgf2n(void)
{
  SshBPoly a, b,c,m;

  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  ssh_bpoly_init(&m);

  /* Construct the modulus. */
  ssh_bpoly_set_ui(&a, 0x0000009);
  ssh_bpoly_set_ui(&b, 0x1000);
  ssh_bpoly_mul_2exp(&b, &b, 32);
  ssh_bpoly_add(&m, &a, &b);

  printf("Modulus: ");
  ssh_bpoly_pretty_print(&m);
  printf("\n");
  
  /* Construct the initial value. */
  ssh_bpoly_set_ui(&a, 3779287753UL);
  ssh_bpoly_set_ui(&b, 2720);
  ssh_bpoly_mul_2exp(&b, &b, 32);
  ssh_bpoly_add(&a, &a, &b);

  printf("Input: ");
  ssh_bpoly_hex_dump(&a);
  printf(" ");
  ssh_bpoly_hex_dump(&m);
  printf("\n");
  
  ssh_bpoly_invert(&b, &a, &m);

  printf("Output: ");
  ssh_bpoly_hex_dump(&b);
  printf("\n");
  
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
  ssh_bpoly_clear(&m);
}

#if 1
void testpoly(void)
{
  SshBPoly a, b, c;
  SshGF2nPoly f, g, h, u, v;
  SshGF2nModuli m;
  unsigned int q, i, n0, n1;
  int bits[10];
  
  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  
  for (i = 0; i < 40; i++)
    {
      printf(".");
      fflush(stdout);
      while (find_irreducible((random() % 200) + 96, bits, 5) == 0)
        {
          printf("x");
          fflush(stdout);
        }

      if (ssh_gf2n_init_mod_bits(&m, bits, 5) == 0)
        continue;
      ssh_gf2n_poly_init(&f, &m);
      ssh_gf2n_poly_init(&h, &m);
      ssh_gf2n_poly_init(&u, &m);
      ssh_gf2n_poly_init(&v, &m);
      ssh_gf2n_poly_init(&g, &m);
      
      ssh_gf2n_poly_random(&f, random() % 20);
      ssh_gf2n_poly_random(&g, random() % 20);
      if (ssh_gf2n_poly_is_zero(&f) ||
          ssh_gf2n_poly_is_zero(&g))
        goto next;

      ssh_gf2n_poly_mul(&h, &f, &g);

      ssh_gf2n_poly_div(&u, &v, &h, &f);
      if (ssh_gf2n_poly_cmp(&u, &g) != 0)
        {
          printf("DIV f not correct.\n");
          printf(" f(x) = ");
          ssh_gf2n_poly_print(&f);
          printf("\n g(x) = ");
          ssh_gf2n_poly_print(&g);
          printf("\n h(x) = ");
          ssh_gf2n_poly_print(&h);
          printf("\n u(x) = ");
          ssh_gf2n_poly_print(&u);
          printf("\n v(x) = ");
          ssh_gf2n_poly_print(&v);
          printf("\n");
          
        }

      ssh_gf2n_poly_div(&u, &v, &h, &g);
      if (ssh_gf2n_poly_cmp(&u, &f) != 0)
        {
          printf("DIV g not correct.\n");
          printf(" f(x) = ");
          ssh_gf2n_poly_print(&f);
          printf("\n g(x) = ");
          ssh_gf2n_poly_print(&g);
          printf("\n h(x) = ");
          ssh_gf2n_poly_print(&h);
          printf("\n u(x) = ");
          ssh_gf2n_poly_print(&u);
          printf("\n v(x) = ");
          ssh_gf2n_poly_print(&v);
          printf("\n");
          
        }

      ssh_gf2n_poly_gcd(&u, &h, &f);
      ssh_gf2n_poly_gcd(&v, &h, &g);

      if (ssh_gf2n_poly_cmp(&v, &g) != 0 ||
          ssh_gf2n_poly_cmp(&u, &f) != 0)
        {
          printf("GCD not correct.\n");
          printf(" f(x) = ");
          ssh_gf2n_poly_print(&f);
          printf("\n g(x) = ");
          ssh_gf2n_poly_print(&g);
          printf("\n h(x) = ");
          ssh_gf2n_poly_print(&h);
          printf("\n u(x) = ");
          ssh_gf2n_poly_print(&u);
          printf("\n v(x) = ");
          ssh_gf2n_poly_print(&v);
          printf("\n");
        }

      ssh_gf2n_poly_gcd(&u, &f, &g);
      ssh_gf2n_poly_set_zero(&h);
      ssh_gf2n_poly_setall(&h, SSH_GF2N_POLY_UI, 0, 1, SSH_GF2N_POLY_END);
      if (ssh_gf2n_poly_cmp(&u, &h) == 0)
        {
          ssh_gf2n_poly_invert(&u, &f, &g);
          ssh_gf2n_poly_mul(&v, &f, &u);
          ssh_gf2n_poly_mod(&v, &v, &g);
          
          ssh_gf2n_poly_set_zero(&h);
          ssh_gf2n_poly_setall(&h, SSH_GF2N_POLY_UI, 0, 1, SSH_GF2N_POLY_END);
          if (ssh_gf2n_poly_cmp(&v, &h) != 0)
            {
              printf("INVERSION not correct.\n");
              printf(" f(x) = ");
              ssh_gf2n_poly_print(&f);
              printf("\n g(x) = ");
              ssh_gf2n_poly_print(&g);
              printf("\n h(x) = ");
              ssh_gf2n_poly_print(&h);
              printf("\n u(x) = ");
              ssh_gf2n_poly_print(&u);
              printf("\n v(x) = ");
              ssh_gf2n_poly_print(&v);
              printf("\n");
            }
        }

    next:
      
      ssh_gf2n_clear_mod(&m);
  
      ssh_gf2n_poly_clear(&f);
      ssh_gf2n_poly_clear(&g);
      ssh_gf2n_poly_clear(&h);
      ssh_gf2n_poly_clear(&u);
      ssh_gf2n_poly_clear(&v);
      
    }
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
}

#endif

void test_gf2n(void)
{
  SshGF2nModuli  gm;
  SshGF2nElement ga, gb, gc;
  SshBPoly bm, ba, bb, bc, r;
  int bits[10], i, j;
  unsigned int n0, n1;
  
  for (i = 0; i < 40; i++)
    {
      printf(".");
      fflush(stdout);

      while (find_irreducible((random() % 200) + 96, bits, 5) == 0)
        {
          printf("x");
          fflush(stdout);
        }

      /* printf(" x^%u + x^%u + 1\n", n1, n0); */
      if (ssh_gf2n_init_mod_bits(&gm, bits, 5) == 0)
        continue;

      ssh_gf2n_init(&ga, &gm);
      ssh_gf2n_init(&gb, &gm);
      ssh_gf2n_init(&gc, &gm);

      ssh_bpoly_init(&bm);
      ssh_bpoly_init(&ba);
      ssh_bpoly_init(&bb);
      ssh_bpoly_init(&bc);
      ssh_bpoly_init(&r);

      ssh_bpoly_set_gf2n_mod(&bm, &gm);

      /* Now do some tricks. */
      for (j = 0; j < 100; j++)
        {
          /* Multiplication tests. */
          ssh_gf2n_poor_rand(&ga);
          ssh_gf2n_poor_rand(&gb);

          ssh_bpoly_set_gf2n(&ba, &ga);
          ssh_bpoly_set_gf2n(&bb, &gb);

          ssh_gf2n_mul(&gc, &ga, &gb);
          ssh_bpoly_mul(&bc, &ba, &bb);
          ssh_bpoly_mod(&bc, &bc, &bm);

          ssh_bpoly_set_gf2n(&r, &gc);
          if (ssh_bpoly_cmp(&r, &bc) != 0)
            {
              printf("error: multiplication!\n");
              printf(" ga = ");
              ssh_gf2n_hex_dump(&ga);
              printf("\n");
              printf(" ba = ");
              ssh_bpoly_hex_dump(&ba);
              printf("\n");
              printf(" gb = ");
              ssh_gf2n_hex_dump(&gb);
              printf("\n");
              printf(" bb = ");
              ssh_bpoly_hex_dump(&bb);
              printf("\n");
              printf(" gc = ");
              ssh_gf2n_hex_dump(&gc);
              printf("\n");
              printf(" bc = ");
              ssh_bpoly_hex_dump(&bc);
              printf("\n");
              abort();
            }

          /* Squaring tests. */
          ssh_gf2n_poor_rand(&ga);

          ssh_bpoly_set_gf2n(&ba, &ga);

          ssh_gf2n_square(&gc, &ga);
          ssh_bpoly_square(&bc, &ba);
          ssh_bpoly_mod(&bc, &bc, &bm);

          ssh_bpoly_set_gf2n(&r, &gc);
          if (ssh_bpoly_cmp(&r, &bc) != 0)
            {
              printf("error: squaring!\n");
              printf(" ga = ");
              ssh_gf2n_hex_dump(&ga);
              printf("\n");
              printf(" ba = ");
              ssh_bpoly_hex_dump(&ba);
              printf("\n");
              printf(" gc = ");
              ssh_gf2n_hex_dump(&gc);
              printf("\n");
              printf(" bc = ");
              ssh_bpoly_hex_dump(&bc);
              printf("\n");
              abort();
            }

          /* Inversion tests. */
          ssh_gf2n_poor_rand(&ga);

          ssh_bpoly_set_gf2n(&ba, &ga);

          ssh_bpoly_invert(&bc, &ba, &bm);
          /*printf(" a = ");
          ssh_bpoly_hex_dump(&ba);
          printf("\n c = ");
          ssh_bpoly_hex_dump(&bc);
          printf("\n");*/
          
          ssh_gf2n_invert(&gc, &ga);

          ssh_gf2n_mul(&gb, &gc, &ga);
          if (ssh_gf2n_cmp_ui(&gb, 1) != 0)
            printf("error: not correct inversion in gf2n.\n");

          ssh_bpoly_set_gf2n(&r, &gc);
          if (ssh_bpoly_cmp(&r, &bc) != 0)
            {
              printf("error: inversion!\n");
              printf(" ga = ");
              ssh_gf2n_hex_dump(&ga);
              printf("\n");
              printf(" ba = ");
              ssh_bpoly_hex_dump(&ba);
              printf("\n");
              printf(" gc = ");
              ssh_gf2n_hex_dump(&gc);
              printf("\n");
              printf(" bc = ");
              ssh_bpoly_hex_dump(&bc);
              printf("\n");
              abort();
            }
        }

      ssh_gf2n_clear(&ga);
      ssh_gf2n_clear(&gb);
      ssh_gf2n_clear(&gc);

      ssh_gf2n_clear_mod(&gm);
      
      ssh_bpoly_clear(&ba);
      ssh_bpoly_clear(&bb);
      ssh_bpoly_clear(&bc);
      ssh_bpoly_clear(&bm);
      ssh_bpoly_clear(&r);
    }  
}

int main(int ac, char *av[])
{
  unsigned int t0, t1;
  int e, k;
  int bits[10];
  unsigned int t = ssh_time();

  srandom(t);
  printf(" GF(2^n) testing...\n");
  test_gf2n();
  printf(" Polynomials over GF(2^n) testing...\n");
  testpoly(); 
  
  /*srandom(t);
  test_function(88, 177);
  srandom(t);
  test_function_gf2n(88, 177); */
  /*testgf2n();
  find_irreducible_trinomial(177, &t0, &t1);
  printf("Trinomial found: x^%u + x^%u + 1\n",
         t1, t0); */
  /*find_ip(16); */
  
  /*
  testpoly();
  */
  
  if (ac < 3)
    {
      printf("usage: %s small exp\n", av[0]);
      printf("Defaulting to 5 31\n");
      e = 5;
      k = 31;
    }
  else
    {
      e = atoi(av[1]);
      k = atoi(av[2]);
    }

  printf("Trying to find an irreducible polynomial of degree %u.\n", e*k);
  if (find_irreducible(e*k, bits, 5) == 0)
    {
      printf("There does not exists a suitable polynomial!\n");
      return 1;
    }
  
  printf("Testing some ec2n code.\n");
  test_ec2n(e, bits, 5);
  return 0;
}
