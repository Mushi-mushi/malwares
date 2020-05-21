/*

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Test time measurement.

*/

/*
 * $Id: t-timemeasure.c,v 1.9 1999/05/04 02:20:32 kivinen Exp $
 * $Log: t-timemeasure.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtimemeasure.h"

/* 
 * START, STOP, RESET and INTERMEDIATE macros are context dependent
 * and expect that there is a double variable `rv' in which operation
 * can store the return value of the operation.
 */
#define START(x)  ((printf("Starting timer %s.\n", #x)),                      \
                   (ssh_time_measure_start(x)),                               \
                   (rv = (double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_SECOND)))


#define STOP(x)   ((printf("Stopping timer %s.\n", #x)),                      \
                   (ssh_time_measure_stop(x)),                                \
                   (rv = (double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_SECOND)))

#define RESET(x)  ((printf("Resetting timer %s.\n", #x)),                     \
                   (rv = (double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_SECOND)), \
                   (ssh_time_measure_reset(x)))


#define INTERMEDIATE(x)                                                       \
                  (printf("Intermediate timer %s (%.12f seconds).\n",         \
                          #x, (rv = ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_SECOND)))))

#define STAMP(x)                                                              \
                  (printf("Stamp timer %s (%lu seconds).\n",                  \
                          #x, ((unsigned long)ssh_time_measure_stamp(x, SSH_TIME_GRANULARITY_SECOND))))

#define MILLISTAMP(x)                                                         \
                  (printf("Stamp timer %s (%lu microseconds).\n",             \
                          #x, ((unsigned long)ssh_time_measure_stamp(x, SSH_TIME_GRANULARITY_MILLISECOND))))

#define MICROSTAMP(x)                                                         \
                  (printf("Stamp timer %s (%lu milliseconds).\n",             \
                          #x, ((unsigned long)ssh_time_measure_stamp(x, SSH_TIME_GRANULARITY_MICROSECOND))))

#define NANOSTAMP(x)                                                          \
                  (printf("Stamp timer %s (%lu nanoseconds).\n",              \
                      #x, ((unsigned long)ssh_time_measure_stamp(x, SSH_TIME_GRANULARITY_NANOSECOND))))

#define CHECKNANOSTAMP(x)                                                     \
                  (printf("Stamp timer %s %s the maximum value.\n",           \
                      #x, (ssh_time_measure_stamp(x, SSH_TIME_GRANULARITY_NANOSECOND) == SSH_TIME_STAMP_MAX) ? "HAS REACHED" : "has not yet reached"))

#define SET(x, s, n)                                                          \
                  ((printf("Set timer %s to %lu sec %lu nsec\n",              \
                           #x, (unsigned long)s, (unsigned long)n)),          \
                   (ssh_time_measure_set_value(x, s, n)))

#define GET_INT(x) STAMP(x)


#define GET_NANOSECONDS(x)                                                    \
                  (printf("Intermediate timer %s (%.12f nanoseconds).\n",     \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_NANOSECOND))))

#define GET_MICROSECONDS(x)                                                   \
                  (printf("Intermediate timer %s (%.12f microseconds).\n",    \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_MICROSECOND))))

#define GET_MILLISECONDS(x)                                                   \
                  (printf("Intermediate timer %s (%.12f milliseconds).\n",    \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_MILLISECOND))))

#define GET_SECONDS(x)                                                        \
                  (printf("Intermediate timer %s (%.12f seconds).\n",         \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_SECOND))))

#define GET_MINUTES(x)                                                        \
                  (printf("Intermediate timer %s (%.12f minutes).\n",         \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_MINUTE))))

#define GET_HOURS(x)                                                          \
                  (printf("Intermediate timer %s (%.12f hours).\n",           \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_HOUR))))

#define GET_DAYS(x)                                                           \
                  (printf("Intermediate timer %s (%.12f days).\n",            \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_DAY))))

#define GET_WEEKS(x)                                                          \
                  (printf("Intermediate timer %s (%.12f weeks).\n",           \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_WEEK))))

#define GET_MONTHS(x)                                                         \
      (printf("Intermediate timer %s (%.12f months (default = sidereal)).\n", \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_MONTH))))

#define GET_MONTHS_2(x)                                                       \
                 (printf("Intermediate timer %s (%.12f months (synodic)).\n", \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_MONTH_SYNODIC))))

#define GET_YEARS(x)                                                          \
      (printf("Intermediate timer %s (%.12f years (default = sidereal)).\n",  \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_YEAR))))

#define GET_YEARS_2(x)                                                        \
                (printf("Intermediate timer %s (%.12f years (tropical)).\n",  \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_YEAR_TROPICAL))))

#define GET_YEARS_3(x)                                                        \
                (printf("Intermediate timer %s (%.12f years (anomalistic)).\n", \
                          #x, ((double)ssh_time_measure_get(x, SSH_TIME_GRANULARITY_YEAR_ANOMALISTIC))))

#ifdef HAVE_USLEEP
#define USLEEP(x)                                                             \
    ((printf("sleep for %.12f seconds.\n", ((double)(x)) / 1000000.0)),       \
     (usleep(x)))
#else /* HAVE_USLEEP */
#define USLEEP(x)                                                             \
    ((printf("sleep for %.12f seconds.\n", ((double)((x)/1000000)))),         \
     (sleep(x / 1000000)))
#endif /* HAVE_USLEEP */

int main()
{
  SshTimeMeasure total_timer;
  SshTimeMeasure timer_1;
  SshTimeMeasure timer_2;
  SshTimeMeasure timer_3;
  SshTimeMeasure timer_4;
  SshTimeMeasure timer_5;
  static struct SshTimeMeasureRec timer_6_rec = SSH_TIME_MEASURE_INITIALIZER;
  SshTimeMeasure timer_6;
  int i;
  double rv = 0.0;
  int ev = 0;
#ifdef HAVE_GETTIMEOFDAY      
  struct timeval tv;
#endif /* HAVE_GETTIMEOFDAY */
  SshUInt64 seconds;
  SshUInt32 nanoseconds;

  total_timer = ssh_time_measure_allocate();
  timer_1 = ssh_time_measure_allocate();
  timer_2 = ssh_time_measure_allocate();
  timer_3 = ssh_time_measure_allocate();
  timer_4 = ssh_time_measure_allocate();
  timer_5 = ssh_time_measure_allocate();
  timer_6 = &timer_6_rec;

  if (ssh_time_measure_get(timer_5, SSH_TIME_GRANULARITY_NANOSECOND) != 0)
    {
      ssh_warning("Weird initial stamp value.\n");
      ev++;
    }
  if (ssh_time_measure_get(timer_6, SSH_TIME_GRANULARITY_NANOSECOND) != 0)
    {
      ssh_warning("Weird initial (static) stamp value.\n");
      ev++;
    }
  rv = (double)ssh_time_measure_get(total_timer, SSH_TIME_GRANULARITY_SECOND); 
  if ((rv < 0.0) || (rv > 0.0))
    {
      ssh_warning("Weird initial value.\n");
      ev++;
    }

  ssh_time_measure_granularity(&seconds, &nanoseconds);
  if ((seconds == 0) && (nanoseconds == 0))
    {
      ssh_warning("Weird granularity.\n");
      ev++;
    }
  else
    {
      printf("granularity is %lu sec %lu nsec\n", 
             (unsigned long)seconds,
             (unsigned long)nanoseconds);
    }

  START(total_timer);
  START(timer_1);
  START(timer_3);
  START(timer_4);
  START(timer_5);

  STAMP(total_timer);

  printf("testing stamps\n");
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  CHECKNANOSTAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  CHECKNANOSTAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  CHECKNANOSTAMP(timer_1);
  USLEEP(1000000);
  NANOSTAMP(timer_1);
  MICROSTAMP(timer_1);
  MILLISTAMP(timer_1);
  STAMP(timer_1);
  CHECKNANOSTAMP(timer_1);
  
  USLEEP(2000000);
  STAMP(total_timer);

  SET(timer_5, 12345, 12345678);
  INTERMEDIATE(timer_5);
  if ((rv < 12345.0) || (rv > 12350.0))
    {
      ssh_warning("Weird intermediate after running set.\n");
      ev++;
    }

  INTERMEDIATE(timer_1);
  if (rv < 1.0)
    {
      ssh_warning("Weird intermediate.\n");
      ev++;
    }
  STOP(timer_3);
  if (rv < 1.0)
    {
      ssh_warning("Weird stop value.\n");
      ev++;
    }
  START(timer_2);
  RESET(timer_4);

  USLEEP(3000000);
  STAMP(total_timer);

  INTERMEDIATE(timer_2);
  INTERMEDIATE(timer_5);
  START(timer_3);
  if (rv < 1.0)
    {
      ssh_warning("Weird restart value.\n");
      ev++;
    }
  RESET(timer_4);
  STOP(timer_1);


  USLEEP(4000000);
  STAMP(total_timer);


  STOP(timer_5);

#ifdef SSHUINT64_IS_64BITS
  printf("Setting timer_5 to big value.\n");
  ssh_time_measure_set_value(timer_5, 
                             ((SshUInt64)0xffffffff) * ((SshUInt64)30), 
                             987654321);
  INTERMEDIATE(timer_5);
  if ((rv < 128849018000.0) || (rv > 128849019000.0))
    {
      ssh_warning("Weird intermediate after stopped set.\n");
      ev++;
    }
#else
  SET(timer_5, 1234567890, 987654321);
  INTERMEDIATE(timer_5);
  if ((rv < 1234567890.0) || (rv > 1234567900.0))
    {
      ssh_warning("Weird intermediate after stopped set.\n");
      ev++;
    }
#endif

  STOP(timer_4);
  STOP(timer_3);
  STOP(timer_2);
  STOP(timer_1);

#define TIMESTAMPS 1000000

  ssh_time_measure_reset(timer_1);
  ssh_time_measure_reset(timer_2);
  printf("\nGenerating %d timestamps.\n", TIMESTAMPS);
  START(timer_2);
  START(timer_1);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      ssh_time_measure_stamp(timer_2, SSH_TIME_GRANULARITY_MICROSECOND);
    }
  STOP(timer_1);
  STOP(timer_2);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         (double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND),
         (double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) / (double)TIMESTAMPS);
  if ((double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / (double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND)));
  printf(")\n");

  ssh_time_measure_reset(timer_3);
  ssh_time_measure_reset(timer_4);
  printf("\nFor reference generating %d timestamps with time(3).\n", 
         TIMESTAMPS);
  START(timer_4);
  START(timer_3);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      ssh_time();
    }
  STOP(timer_3);
  STOP(timer_4);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND),
         (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) / (double)TIMESTAMPS);
  if ((double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND)));
  printf(")\n");

  if (((double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) > 0.0) &&
      ((double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) > 0.0))
    printf("Using time(3) is %2.1f%% faster than ssh_..._stamp.\n", 
           (((double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) - 
             (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND)) /
            (double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND)) * 100.0);

#ifdef HAVE_GETTIMEOFDAY
  ssh_time_measure_reset(timer_3);
  ssh_time_measure_reset(timer_4);
  printf("\nFor reference generating %d timestamps with gettimeofday.\n", 
         TIMESTAMPS);
  START(timer_4);
  START(timer_3);
  for (i = 1; i < TIMESTAMPS; i++)
    {
      gettimeofday(&tv, NULL);
    }
  STOP(timer_3);
  STOP(timer_4);
  printf("Time elapsed %.12f seconds (%.12f seconds/timestamp", 
         (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND),
         (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) / (double)TIMESTAMPS);
  if ((double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) > 0.0)
    printf(", %d timestamps/second",
           (int)((double)TIMESTAMPS / (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND)));
  printf(")\n");

  if (((double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) > 0.0) &&
      ((double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND) > 0.0))
    printf("Using gettimeofday(3) is %2.1f%% faster than ssh_..._stamp.\n", 
           (((double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND) - 
             (double)ssh_time_measure_get(timer_3, SSH_TIME_GRANULARITY_SECOND)) /
            (double)ssh_time_measure_get(timer_1, SSH_TIME_GRANULARITY_SECOND)) * 100.0);
#endif /* HAVE_GETTIMEOFDAY */

  printf("making start stop test. timers are silently started and stopped.\n");
  printf("timer_3 runs while timer_4 is started and stopped in loop.\n");
  ssh_time_measure_stop(timer_3);
  ssh_time_measure_stop(timer_4);
  ssh_time_measure_reset(timer_3);
  ssh_time_measure_reset(timer_4);
  ssh_time_measure_start(timer_3);
  for (i = 0; i < 1000000; i++)
    {
      ssh_time_measure_start(timer_4);
      ssh_time_measure_stop(timer_4);
    }
  ssh_time_measure_stop(timer_3);
  INTERMEDIATE(timer_4);
  INTERMEDIATE(timer_3);
  

  STOP(total_timer);
  GET_INT(timer_1);
  INTERMEDIATE(timer_1);
  GET_INT(timer_2);
  INTERMEDIATE(timer_2);
  GET_INT(timer_3);
  INTERMEDIATE(timer_3);
  GET_INT(timer_4);
  INTERMEDIATE(timer_4);
  GET_INT(timer_5);
  INTERMEDIATE(timer_5);
  GET_INT(total_timer);
  INTERMEDIATE(total_timer);
  printf("Testing granularities\n");
  GET_NANOSECONDS(total_timer);
  GET_MICROSECONDS(total_timer);
  GET_MILLISECONDS(total_timer);
  GET_SECONDS(total_timer);
  GET_MINUTES(total_timer);
  GET_HOURS(total_timer);
  GET_DAYS(total_timer);
  GET_WEEKS(total_timer);
  GET_MONTHS(total_timer);
  GET_YEARS(total_timer);
  GET_NANOSECONDS(timer_5);
  GET_MICROSECONDS(timer_5);
  GET_MILLISECONDS(timer_5);
  GET_SECONDS(timer_5);
  GET_MINUTES(timer_5);
  GET_HOURS(timer_5);
  GET_DAYS(timer_5);
  GET_WEEKS(timer_5);
  GET_MONTHS(timer_5);
  GET_MONTHS_2(timer_5);
  GET_YEARS(timer_5);
  GET_YEARS_2(timer_5);
  GET_YEARS_3(timer_5);

  ssh_time_measure_free(timer_5);
  ssh_time_measure_free(timer_4);
  ssh_time_measure_free(timer_3);
  ssh_time_measure_free(timer_2);
  ssh_time_measure_free(timer_1);
  ssh_time_measure_free(total_timer);

  exit(ev);
}

