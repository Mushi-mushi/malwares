/*

Authors: Timo J. Rinne <tri@ssh.fi>
         Tero Kivinen <kivinen@ssh.fi>
         Tero Mononen <tmo@ssh.fi>
         Sami Lehtinen <sjl@ssh.fi> (junior member of the group)

Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Calendar time retrieval and manipulation.

*/

#ifndef SSHTIME_H
#define SSHTIME_H

typedef SshInt64 SshTime;
typedef struct SshCalendarTimeRec *SshCalendarTime;

struct SshCalendarTimeRec {
  SshUInt8 second;     /* 0-61 */
  SshUInt8 minute;     /* 0-59 */
  SshUInt8 hour;       /* 0-23 */
  SshUInt8 monthday;   /* 1-31 */
  SshUInt8 month;      /* 0-11 */
  SshInt32 year;       /* Absolute value of year.  1999=1999. */
  SshUInt8 weekday;    /* 0-6, 0=sunday */
  SshUInt16 yearday;   /* 0-365 */
  SshInt32 utc_offset; /* Seconds from UTC (positive=east) */
  Boolean dst;         /* FALSE=non-DST, TRUE=DST */
};

/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  */
SshTime ssh_time(void);

/* Fills the calendar structure according to ``current_time''. */
void ssh_calendar_time(SshTime current_time,
                       SshCalendarTime calendar_ret,
                       Boolean local_time);

/* Return time string in RFC-2550 compatible format.  Returned string
   is allocated with ssh_xmalloc and has to be freed with ssh_xfree by
   the caller. */
char *ssh_time_string(SshTime input_time);

/* Return a time string that is formatted to be more or less human
   readable.  It is somewhat like the one returned by ctime(3) but
   contains no newline in the end.  Returned string is allocated with
   ssh_xmalloc and has to be freed with ssh_xfree by the caller. */
char *ssh_readable_time_string(SshTime input_time, Boolean local_time);

#endif /* SSHTIME_H */

/* eof (sshtime.h) */
