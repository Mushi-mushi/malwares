/*

  timeit.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Sep  4 00:58:25 1996 [mkojo]

  Simple timing routines.

  */

/*
 * $Id: timeit.h,v 1.4 1999/04/24 01:53:45 mkojo Exp $
 * $Log: timeit.h,v $
 * $EndLog$
 */

#ifndef TIMEIT_H
#define TIMEIT_H

#if defined(__DECC) && defined(__alpha)
#include <c_asm.h>
#endif

/* The timeit context */

typedef struct TimeItRec
{
  double real_secs, real_usecs;
  double process_secs;
  double cpu_time;
  double cycles;
  
  /* These are private */
#if defined(HAVE_GETTIMEOFDAY)
  struct timeval prv_s_tv;
  struct timezone prv_s_tz;
#endif /* HAVE_GETTIMEOFDAY */
#if defined(HAVE_CLOCK)
  clock_t prv_ticks;
#endif /* HAVE_CLOCK */

  /* Cycles, only 1,2,3,or 4 are used here. */
  unsigned long prv_c[4];
  
} TimeIt;

/* Start timing */

static inline void cycles_timing(unsigned long *in_c, unsigned long *out_c)
{
  /* Jump into the cycle counting thing. */
  
#if defined(__GNUC__) && (defined(__i486) || defined(__i386) || defined(__i586))
  static unsigned int  a, d, t0, t1;

  /* We have a Pentium here. Hence, we try computing the 64-bit cycle
     here, however, please note that such computation is inherently
     taking few cycles itself. Thus computing cycles in general seems
     to be non-exact science. */
  
  t0 = in_c[0];
  t1 = in_c[1];
  
  /* Use the cycle counting instruction. */
  /* __asm__("rdtsc" : "=a" (a), "=d" (d):); */
  __asm__(".byte 0x0f,0x31; sub %2, %%eax; subb %3, %%edx"
          : "=a" (a), "=d" (d)
          : "rm" (t0), "rm" (t1));
  
  /* Supply the output. */
  out_c[0] = a;
  out_c[1] = d;
#define CYCLE_COUNTER
#endif

#if defined(WINDOWS) && defined(WIN32)
  static unsigned long t0, t1, a, d;

  t0 = in_c[0];
  t1 = in_c[1];

  /* Inline assembler for Windows 32-bit platform. */
  __asm rdtsc
  __asm sub  eax, t0
  __asm subb edx, t1
  __asm mov  a,   eax
  __asm mov  d,   edx

  out_c[0] = a;
  out_c[1] = d;
#define CYCLE_COUNTER
#endif
                                    
  
#if defined(__GNUC__) && defined(__alpha)
  static unsigned long c = 0;
  __asm__("rpcc %0" : "=r" (c):);
  out_c[0] = (c + (c >> 32) - in_c[0]) & 0xffffffff;
#define CYCLE_COUNTER
  
#elif defined(__DECC) && defined(__alpha)
  static unsigned long c = 0;
  c = asm("rpcc %v0");
  out_c[0] = (c + (c >> 32) - in_c[0]) & 0xffffffff;
#define CYCLE_COUNTER
  
#endif /* Alpha */

#ifndef CYCLE_COUNTER
  /* Cycle counter not defined! */
  out_c[0] = out_c[1] = out_c[2] = out_c[3] = 0;
#endif /* CYCLE_COUNTER */
}


static void start_timing(TimeIt *tmit)
{
  tmit->real_secs    = 0;
  tmit->real_usecs   = 0;
  tmit->process_secs = 0;
  tmit->cycles       = 0;
  
#if defined(HAVE_GETTIMEOFDAY)
  gettimeofday(&tmit->prv_s_tv, &tmit->prv_s_tz);
#endif /* HAVE_GETTIMEOFDAY */

#if defined(HAVE_CLOCK)
  tmit->prv_ticks = clock();
#endif /* HAVE_CLOCK */

  /* Initialize the cycle couting table. */
  tmit->prv_c[0] = tmit->prv_c[1] = tmit->prv_c[2] = tmit->prv_c[3] = 0;
  cycles_timing(tmit->prv_c, tmit->prv_c);
}

/* End timing */

static void check_timing(TimeIt *tmit)
{
#if defined(HAVE_GETTIMEOFDAY)
  static struct timeval e_tv;
  static struct timezone e_tz;
#endif /* HAVE_GETTIMEOFDAY */
#if defined(HAVE_CLOCK)
  static clock_t fini;
#endif /* HAVE_CLOCK */
  static unsigned long c[4];

  /* Get the cycles first, as they are most accurate on most platforms. */
  cycles_timing(tmit->prv_c, c);

#if defined(HAVE_CLOCK)
  /* Clock might be often quite accurate, hence use it. */
  fini = clock();
#endif /* HAVE_CLOCK */

#if defined(HAVE_GETTIMEOFDAY)
  /* Getting time of day is sometimes less useful. */
  gettimeofday(&e_tv, &e_tz);

  /* Compute times */
  
  tmit->real_usecs = (((double)e_tv.tv_sec) * 1000000.0
                      + (double)e_tv.tv_usec) -
    (((double)tmit->prv_s_tv.tv_sec) * 1000000.0 +
     (double)tmit->prv_s_tv.tv_usec);
  tmit->real_secs = tmit->real_usecs / 1000000.0;
#endif /* HAVE_GETTIMEOFDAY */

#if defined(HAVE_CLOCK)
  /* If no cycle information then use the clock as it sometimes is
     ok. */
  tmit->process_secs = ((double)fini - tmit->prv_ticks) /
    (double)CLOCKS_PER_SEC;

#if defined(HAVE_GETTIMEOFDAY)
  if (tmit->real_secs > 0.0)
    tmit->cpu_time = tmit->process_secs / tmit->real_secs;
  else
    tmit->cpu_time = 0.0;
#endif /* HAVE_GETTIMEOFDAY */
#endif /* HAVE_CLOCK */
  
  /* Explain cycles. */
  tmit->cycles = (double)(c[0]);
}

#endif /* TIMEIT_H */
