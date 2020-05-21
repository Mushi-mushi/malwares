/*

Authors: Timo J. Rinne <tri@ssh.fi>
         Tero Kivinen <kivinen@ssh.fi>
         Tero Mononen <tmo@ssh.fi>
         Sami Lehtinen <sjl@ssh.fi> (junior member of the group)

Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Calendar time retrieval and manipulation.

*/

#include "sshincludes.h"
#include "sshdsprintf.h"
#undef time

#define SSH_DEBUG_MODULE "SshTime"

/* Returns seconds that local timezone is east from the UTC meridian
   and boolean which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If 
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
void ssh_get_local_timezone(SshTime tv,
                            SshInt32 *utc_offset,
                            Boolean *dst);

/* Array that tells how many days each month of the year have.
   Variable monthday[1] has to be fixed to 28 or 29 depending
   on the year we are referring to. */
static const SshUInt8 monthdays[12] = { 31, 28, 31, 30, 31, 30, 
                                        31, 31, 30, 31, 30, 31 };

/* Arrays of weekday and month names.  These are used by 
   ssh_readable_time_string to generate ctime(3) like
   output string from the SshTime value. */
static const char *abbr_day[] = { "Sun", "Mon", "Tue", "Wed", 
                                  "Thu", "Fri", "Sat", NULL };

static const char *abbr_month[] = { "Jan", "Feb", "Mar", "Apr", 
                                    "May", "Jun", "Jul", "Aug", 
                                    "Sep", "Oct", "Nov", "Dec", 
                                    NULL };

/* Check if a year is a leap year (i.e. 29 days in February, 366 days in year)
   according to gregorian calendar.
     - Every year divisible by 400 is a leap year.
     - Year divisible by 4 is a leap year, if it is NOT divisible by 100.
     - Otherwise year is not a leap year.
*/
#define SSH_IS_LEAP_YEAR(y) ((((y) % 400) == 0) || \
                             ((((y) % 4) == 0) && (((y) % 100) != 0)))

/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
SshTime ssh_time(void)
{
  return (SshTime)(time(NULL));
}

/* Fills the calendar structure according to ``current_time''.  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void ssh_calendar_time(SshTime input_time,
                       SshCalendarTime calendar_ret,
                       Boolean local_time)
{
  /*
   * Naive implementation of calendar time.  This implementation
   * ignores timezones and leap seconds but is otherwise
   * (way beyond) Y2K compatible.
   * This implementation follows the Gregorian calendar even before
   * the Gregorian calendar was invented.  This is really not right
   * if we want to present dates before the 17th century.
   */
  SshInt64 day;
  SshInt64 sec;

  if (local_time)
    {
      ssh_get_local_timezone(input_time,
                             &(calendar_ret->utc_offset),
                             &(calendar_ret->dst));
      input_time += (SshTime)(calendar_ret->utc_offset);
    }
  else
    {
      calendar_ret->utc_offset = 0;
      calendar_ret->dst = FALSE;
    }
  if (input_time >= 0)
    {
      /* Calculate day of the year and second of the day.  Weekday 
         calculation is based on the fact that 1.1.1970 (the epoch day)
         was Thursday. */
      day = input_time / 86400;
      sec = input_time % 86400;
      calendar_ret->weekday = (day + 4) % 7;
    }
  else
    {
      /* Ensure that we have positive day of the year, second of the
         day and day of the week also if we have nedative time value
         measured from the epoch. */
      day = (-(((-input_time) - 1) / 86400)) - 1;
      sec = 86399 - (((-input_time) - 1) % 86400);
      calendar_ret->weekday = 6 - (((-day) + 2) % 7);
    }
  /* Start calculation from the epoch year.  If we are on the negative side
     or more than 400 years beyond 1970, we adjust the year so, that we 
     need to iterate only years from the last even 400 years.  
     146097 is the number of days in each 400 years in Gregorian era. */
  calendar_ret->year = 1970;
  if (day < 0)
    {
      day = -day;
      calendar_ret->year -= ((day / 146097) * 400) + 400;
      day = -((day % 146097) - 146097);
    }
  else if (day >= 146097)
    {
      calendar_ret->year += ((day / 146097) * 400);
      day = day % 146097;
    }
  /* Iterate years until we have number of days that fits in the 
     ``current'' year. */ 
  do {
    if (day < (365 + (SSH_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0)))
      break;
    day -= 365 + (SSH_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0);
    calendar_ret->year++;    
  } while (1);
  /* There is no year 0. */
  if (calendar_ret->year <= 0)
    calendar_ret->year -= 1;
  /* Day of the year we got as a by product of year calculation. */
  calendar_ret->yearday = (SshUInt16)day;
  /* Now we can trivially calculate seconds, minutes and hours. */
  calendar_ret->second = (SshUInt8)(sec % 60);
  calendar_ret->minute = (SshUInt8)((sec % 3600) / 60);
  calendar_ret->hour = (SshUInt8)(sec / 3600);
  /* Now we iterate the month.  Leap years make this a bit bitchy. */
  calendar_ret->month = 0;
  do {
    SSH_ASSERT(calendar_ret->month < 12);
    if (day < (monthdays[calendar_ret->month] +
               (((calendar_ret->month == 1) && 
                 (SSH_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0)))
      break;
    day -= (monthdays[calendar_ret->month] +
            (((calendar_ret->month == 1) && 
              (SSH_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0));
    calendar_ret->month++;
  } while(1);
  /* Day of the month is a leftover from the month calculation. */
  calendar_ret->monthday = (SshUInt8)(day + 1);
  return;
}

/* Return time string in RFC-2550 compatible format.  Returned string
   is allocated with ssh_xmalloc and has to be freed with ssh_xfree by
   the caller.  This implementation is only a subset of RFC-2550 and
   is valid only between years 0-9999.  Fix this before Y10K problem
   is imminent. */
char *ssh_time_string(SshTime input_time)
{
  struct SshCalendarTimeRec calendar[1];
  char *r;

  ssh_calendar_time(input_time, calendar, FALSE);
  ssh_dsprintf(&r, "%04d%02d%02d%02d%02d%02d",
               (int)calendar->year,
               (int)calendar->month + 1,
               (int)calendar->monthday,
               (int)calendar->hour,
               (int)calendar->minute,
               (int)calendar->second);
  return r;
}

char *ssh_readable_time_string(SshTime input_time, Boolean local_time)
{
  struct SshCalendarTimeRec calendar[1];
  char zoneid[8];
  char *r;
  
  ssh_calendar_time(input_time, calendar, local_time);

  if (calendar->utc_offset == 0)
    {
      zoneid[0] = '\0';
    }
  else if (calendar->utc_offset > 0)
    {
      snprintf(zoneid, sizeof (zoneid), " +%02d%02d",
               (int)((calendar->utc_offset / 3600) % 100),
               (int)((calendar->utc_offset / 60) % 60));
    }
  else
    {
      snprintf(zoneid, sizeof (zoneid), " -%02d%02d",
               (int)(((- calendar->utc_offset) / 3600) % 100),
               (int)(((- calendar->utc_offset) / 60) % 60));
    }
  
  ssh_dsprintf(&r, "%s %s %02d %04d %02d:%02d:%02d%s",
               abbr_day[calendar->weekday % 7],
               abbr_month[calendar->month % 12],
               (int)calendar->monthday,
               (int)calendar->year,
               (int)calendar->hour,
               (int)calendar->minute,
               (int)calendar->second,
               zoneid);
  return r;
}

/* Returns seconds that local timezone is east from the UTC meridian
   and boolean which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If 
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
void ssh_get_local_timezone(SshTime tv,
                            SshInt32 *utc_offset,
                            Boolean *dst)
{
#if ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME)
  struct tm *tm;
  time_t t;
  struct SshCalendarTimeRec ct[1];

  /* We trust localtime(3) for dst interpretation 1970-2037.
     Before this timeframe, we just check localtime for
     Jan 1 1998, which should work more or less everywhere. 
     After 2037 we normalize this date to year 2037 and 
     call system localtime(3) for that. */
  if ((tv > ((SshTime)0)) && (tv < ((SshTime)2145916800)))
    {
      t = (time_t)tv;
    }
  else if (tv >= ((SshTime)2145916800))
    {
      ssh_calendar_time(tv, ct, FALSE);
      if (SSH_IS_LEAP_YEAR(ct->year))
        t = (time_t)2082758400; /* 1.1.2036 */
      else
        t = (time_t)2114380800; /* 1.1.2037 */
      t += ((((time_t)86400) * ((time_t)(ct->yearday))) +
            (((time_t)3600) * ((time_t)(ct->hour))) +
            (((time_t)60) * ((time_t)(ct->minute))) +
            ((time_t)(ct->second)));
    }
  else
    {
      t = (time_t)883656061; /* Thu Jan 1 12:01:01 1998 UTC */
    }
#undef localtime
  tm = localtime(&t);
#ifdef HAVE_TM_GMTOFF_IN_STRUCT_TM
  if ((tm != NULL) && 
      (tm->tm_gmtoff >= (-50400)) &&
      (tm->tm_gmtoff <= 50400))
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)(tm->tm_gmtoff);
    }
  else
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)0;
    }
#else /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
  if (utc_offset != NULL)
    *utc_offset = (SshInt32)0;
#endif /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
#ifdef HAVE_TM_ISDST_IN_STRUCT_TM
  if (tm != NULL)
    {
      if (dst != NULL)
        *dst = (tm->tm_isdst != 0);
    }
  else
    {
      if (dst != NULL)
        *dst = FALSE;
    }
#else /* HAVE_TM_ISDST_IN_STRUCT_TM */
  if (dst != NULL)
    *dst = FALSE;
#endif /* HAVE_TM_ISDST_IN_STRUCT_TM */
#else /* ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME) */
  if (utc_offset != NULL)
    *utc_offset = (SshInt32)0;
  if (dst != NULL)
    *dst = FALSE;
#endif /* ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME) */
}

/* eof (sshtime.c) */
