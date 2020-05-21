/*

t-time.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Created: Fri Apr 23 07:58:12 1999 tri

*/

#include "sshincludes.h"

void check_time(SshTime tv, int year, int month, int day)
{
  struct SshCalendarTimeRec ct[1];

  ssh_calendar_time(tv, ct, FALSE);
  if ((ct->year != year) || 
      ((ct->month + 1) != month) ||
      (ct->monthday != day))
    {
      fprintf(stderr, "ssh_calendar_time returns %04d-%02d-%02d\n",
              (int)ct->year, (int)ct->month + 1, (int)ct->monthday);
      fprintf(stderr, "reference value is %04d-%02d-%02d\n",
              year, month, day);
      exit(1);
    }
  return;
}

int main()
{
  int i, j, k, d, y, p;
  char *a, *b, *first, *last, *rfirst, *rlast;
  SshTime t;
  struct SshCalendarTimeRec ct[1];

  t = ssh_time();
  a = ssh_time_string(t);
  first = ssh_xstrdup(a);
  rfirst = ssh_readable_time_string(t, TRUE);
  printf("First value was \"%s\" (%s).\n", first, rfirst);
  for (i = 0; i < 5; i++)
    {
      for (j = 0; j < 100; j++)
        for (k = 0; k < 1000; k++)
          {
            b = ssh_time_string(ssh_time());
            if (strcmp(a, b) > 0)
              {
                fprintf(stderr, 
                        "t-time: ssh_time_string returned value "
                        "\"%s\" after \"%s\", which doesn't sort right.\n",
                        b, a);
                exit(1);
              }
            ssh_xfree(a);
            a = b;
          }
      printf("Intermediate value #%d was \"%s\".\n", i + 1, a);
    }
  ssh_xfree(a);
  t = ssh_time();
  last = ssh_time_string(t);
  rlast = ssh_readable_time_string(t, TRUE);
  printf("First value was \"%s\" (%s).\n", first, rfirst);
  printf("Last value was \"%s\" (%s).\n", last, rlast);
  ssh_xfree(first);
  ssh_xfree(rfirst);
  ssh_xfree(last);
  ssh_xfree(rlast);
  check_time((SshTime)23200,       1970,  1,  1);   /* 01.01.1970 */
  check_time((SshTime)68212800,    1972,  2, 29);   /* 29.02.1972 */
  check_time((SshTime)946641600,   1999, 12, 31);   /* 31.12.1999 */
  check_time((SshTime)946728000,   2000,  1,  1);   /* 01.01.2000 */
  check_time((SshTime)951825600,   2000,  2, 29);   /* 29.02.2000 */
  check_time((SshTime)2147428800,  2038,  1, 18);   /* 18.01.2038 */
#define T_TIME_TEST_COUNT 250000
  {
    t = ((SshTime)43200) - (((SshTime)86400) * ((SshTime)T_TIME_TEST_COUNT));
    ssh_calendar_time(t, ct, FALSE);
    a = ssh_readable_time_string(t, TRUE);
    printf("Testing weekday consistency from: %s\n", a);
    printf("Be aware that days are in the Gregorian system "
           "even before the Gregorian era.\n");
    ssh_xfree(a);
    d = ct->weekday;
    y = ct->year;
    if ((d < 0) || (d > 6))
      {
        fprintf(stderr, 
                "ssh_calendar_time returns %04d-%02d-%02d "
                "with wrong weekday %d\n",
                (int)ct->year, 
                (int)ct->month + 1, 
                (int)ct->monthday,
                (int)ct->weekday);
        exit(1);
      }
    p = d;
    for (i = 0; i < (T_TIME_TEST_COUNT * 2); i++)
      {
        t += 86400;
        ssh_calendar_time(t, ct, FALSE);
        d = (int)ct->weekday;
        if ((d < 0) || (d > 6) || (d != ((p + 1) % 7)))
          {
            fprintf(stderr, 
                    "ssh_calendar_time returns %04d-%02d-%02d "
                    "with inconsistent weekday %d\n",
                    (int)ct->year, 
                    (int)ct->month + 1, 
                    (int)ct->monthday,
                    (int)ct->weekday);
            exit(1);
          }
#if 1
        if ((((ct->year % 100) == 0) && 
             (ct->month == 0) && 
             (ct->monthday == 1)) ||
            (((((ct->year - 20) % 100) == 0) && 
              (ct->month == 5) && 
              (ct->monthday == 24))))
#endif
          {
            a = ssh_readable_time_string(t, TRUE);
            b = ssh_readable_time_string(t, FALSE);
            printf("Intermediate: %s (universal)\n",b);
            printf("              %s (local)\n", a);
            ssh_xfree(a);
            ssh_xfree(b);
          }
        p = d;
        y = ct->year;
      }
  }
  a = ssh_readable_time_string(t, TRUE);
  printf("Weekday consistency tested until: %s\n", a);
  ssh_xfree(a);
  exit(0);
}

/* eof (t-time.c) */
