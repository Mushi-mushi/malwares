/*

  timeit.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Sep  4 00:58:25 1996 [mkojo]

  Simple timing routines.

  */

/*
 * $Id: timeit.h,v 1.5 1998/10/04 02:49:35 ylo Exp $
 * $Log: timeit.h,v $
 * $EndLog$
 */

#ifndef TIMEIT_H
#define TIMEIT_H

#if defined(HAVE_CLOCK) && defined(HAVE_GETTIMEOFDAY)

/* The timeit context */

typedef struct TimeItRec
{
  double real_secs, real_usecs;
  double process_secs;
  double cpu_time;

  /* These are private */
  struct timeval s_tv;
  struct timezone s_tz;
  clock_t ticks;
} TimeIt;

/* Start timing */

void start_timing(TimeIt *tmit)
{
  tmit->real_secs = 0;
  tmit->real_usecs = 0;
  tmit->process_secs = 0;
  
  gettimeofday(&tmit->s_tv, &tmit->s_tz);

  tmit->ticks = clock();
}

/* End timing */

void check_timing(TimeIt *tmit)
{
  struct timeval e_tv;
  struct timezone e_tz;
  clock_t fini;

  fini = clock();
  gettimeofday(&e_tv, &e_tz);

  /* Compute times */
  
  tmit->real_usecs = (((double)e_tv.tv_sec) * 1000000 + (double)e_tv.tv_usec) -
    (((double)tmit->s_tv.tv_sec) * 1000000 + (double)tmit->s_tv.tv_usec);
  tmit->real_secs = tmit->real_usecs / 1000000;

  tmit->process_secs = ((double)fini - tmit->ticks) / CLOCKS_PER_SEC;
  if (tmit->real_secs > 0.0000001)
    tmit->cpu_time = tmit->process_secs / tmit->real_secs;
  else
    tmit->cpu_time = 0.0;
}

#else

/* We cannot do any timing with gettimeofday() or clock() functions. */

typedef struct TimeItRec
{
  double real_secs, real_usecs;
  double process_secs;
  double cpu_time;
} TimeIt;

void start_timing(TimeIt *tmit)
{
  /* Output just zeros, which should indicate that timing isn't working. */
  tmit->real_secs = 0.0;
  tmit->real_usecs = 0.0;
  tmit->process_secs = 0.0;
  tmit->cpu_time = 0.0;
}

void check_timing(TimeIt *tmit)
{
  /* Do something */
}
#endif /* !HAVE_CLOCK && !HAVE_GETTIMEOFDAY */

#endif /* TIMEIT_H */
