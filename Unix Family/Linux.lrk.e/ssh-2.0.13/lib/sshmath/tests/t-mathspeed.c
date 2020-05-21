/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: mathspeed
 *        $Source: /ssh/CVS/src/lib/sshmath/tests/t-mathspeed.c,v $
 *        $Author: kivinen $
 *
 *        Creation          : 18:00 Jul 21 1998 kivinen
 *        Last Modification : 04:11 May  4 1999 kivinen
 *        Last check in     : $Date: 1999/05/04 02:19:53 $
 *        Revision number   : $Revision: 1.4 $
 *        State             : $State: Exp $
 *        Version           : 1.70
 *
 *        Description       : Test math library speed.
 *
 *
 *        $Log: t-mathspeed.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sshmp.h"
#include "timeit.h"


void speed_test(int bits)
{
  SshInt a, b, c, g, r, q;
  SshIntModQ am, bm, gm, rm, qm;
  SshIntModuli m;
  int i, cnt;
  TimeIt tmit;

  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&g);
  ssh_mp_init(&r);
  ssh_mp_init(&q);

  ssh_mp_rand(&a, bits);
  ssh_mp_rand(&b, bits);
  ssh_mp_set_bit(&b, 0);
  ssh_mp_rand(&c, bits);
  ssh_mp_set_bit(&c, 0);
  ssh_mp_set_ui(&g, 2);

  /* Set the highest bit of all the important values. */
  ssh_mp_set_bit(&a, bits);
  ssh_mp_set_bit(&b, bits);
  ssh_mp_set_bit(&c, bits);
  ssh_mp_set_bit(&g, bits);
  
  ssh_mpm_init_m(&m, &c);
  ssh_mpm_init(&am, &m);
  ssh_mpm_init(&bm, &m);
  ssh_mpm_init(&gm, &m);
  ssh_mpm_init(&rm, &m);
  ssh_mpm_init(&qm, &m);

  ssh_mpm_set_mp(&am, &a);
  ssh_mpm_set_mp(&bm, &b);
  ssh_mpm_set_mp(&gm, &g);

  ssh_mp_mul(&c, &a, &b);

#define TEST_IT(test_name,label_name,operation,init_count) \
  printf("%s test...", (test_name)); \
  cnt = init_count; \
label_name: \
  fflush(stdout); \
  start_timing(&tmit); \
  for (i = 0; i < cnt; i++) \
    { \
      operation; \
    } \
  check_timing(&tmit); \
  if (tmit.process_secs < 2.0) \
    { \
      cnt *= 5; \
      printf("%d...", cnt); \
      goto label_name; \
    } \
  printf("done, %s speed = %f us\n", (test_name), \
         tmit.process_secs / cnt * 1000 * 1000);

  TEST_IT("Addition", add_label, ssh_mp_add(&r, &a, &b), 100000);
  TEST_IT("Subraction", sub_label, ssh_mp_sub(&r, &a, &b), 100000);
  TEST_IT("Multiplication", mul_label, ssh_mp_mul(&r, &a, &b), 100000);
  TEST_IT("Square", sqr_label, ssh_mp_square(&r, &a), 100000);
  TEST_IT("Division", div_label, ssh_mp_div(&q, &r, &c, &a), 100000);
  TEST_IT("Division q", div_q_label, ssh_mp_div_q(&q, &c, &a), 100000);
  TEST_IT("Modulo", mod_label, ssh_mp_mod(&r, &c, &b), 100000);
  TEST_IT("Gcd", gcd_label, ssh_mp_gcd(&r, &a, &b), 100);
  TEST_IT("Powm naive", powm_naive_label,
          ssh_mp_powm_naive(&r, &g, &a, &b), 100);
  TEST_IT("Powm bsw", powm_bsw_label, ssh_mp_powm_bsw(&r, &g, &a, &b), 100);
  TEST_IT("Powm naive mont", powm_naive_mont_label,
          ssh_mp_powm_naive_mont(&r, &g, &a, &b), 100);
  TEST_IT("Powm bsw mont", powm_bsw_mont_label,
          ssh_mp_powm_bsw_mont(&r, &g, &a, &b), 100);
  /* TEST_IT("Pow", pow_label, ssh_mp_pow(&r, &a, &b), 1); */

  TEST_IT("Mod add", madd_label, ssh_mpm_add(&rm, &am, &bm), 100000);
  TEST_IT("Mod sub", msub_label, ssh_mpm_sub(&rm, &am, &bm), 100000);
  TEST_IT("Mod mul", mmul_label, ssh_mpm_mul(&rm, &am, &bm), 100000);
  TEST_IT("Mod square", msqr_label, ssh_mpm_square(&rm, &am), 100000);

  ssh_mpm_clear(&am);
  ssh_mpm_clear(&bm);
  ssh_mpm_clear(&gm);
  ssh_mpm_clear(&rm);
  ssh_mpm_clear(&qm);

  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&g);
  ssh_mp_clear(&r);
  ssh_mp_clear(&q);
}

void usage(void)
{
  printf("usage: t-mathspeed [bits]\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int bits;
  
  /* Randomize the random number generator. */
  srandom(ssh_time());

  bits = 1024;

  if (argc == 2)
    {
      bits = atoi(argv[1]);
    }
  else if (argc != 1)
    usage();
  speed_test(bits);
  return 0;
}
