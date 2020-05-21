/* nice -- run a program with modified scheduling priority
   Copyright (C) 90, 91, 92, 93, 94, 95, 1996 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* David MacKenzie <djm@gnu.ai.mit.edu> */

#include <config.h>
#include <stdio.h>

#define NDEBUG
#include <assert.h>

#include <getopt.h>
#include <sys/types.h>
#ifndef NICE_PRIORITY
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include "system.h"
#include "long-options.h"
#include "error.h"

#ifdef NICE_PRIORITY
#define GET_PRIORITY() nice (0)
#else
#define GET_PRIORITY() getpriority (PRIO_PROCESS, 0)
#endif

static int isinteger __P ((char *s));
static void usage __P ((int status));

/* The name this program was run with. */
char *program_name;

static struct option const longopts[] =
{
  {"adjustment", required_argument, NULL, 'n'},
  {NULL, 0, NULL, 0}
};

int
main (int argc, char **argv)
{
  int current_priority;
  int adjustment = 0;
  int minusflag = 0;
  int adjustment_given = 0;
  int i;

  program_name = argv[0];
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  parse_long_options (argc, argv, "nice", GNU_PACKAGE, VERSION, usage);

  for (i = 1; i < argc; /* empty */)
    {
      char *s = argv[i];

      if (s[0] == '-' && s[1] == '-' && ISDIGIT (s[2]))
	{
	  if (!isinteger (&s[2]))
	    error (1, 0, _("invalid option `%s'"), s);

	  minusflag = 1;
	  /* FIXME: use xstrtol */
	  adjustment = atoi (&s[2]);
	  adjustment_given = 1;
	  ++i;
	}
      else if (s[0] == '-' && (ISDIGIT (s[1])
			       || (s[1] == '+' && ISDIGIT (s[2]))))
	{
	  if (s[1] == '+')
	    ++s;
	  if (!isinteger (&s[1]))
	    error (1, 0, _("invalid option `%s'"), s);

	  minusflag = 0;
	  /* FIXME: use xstrtol */
	  adjustment = atoi (&s[1]);
	  adjustment_given = 1;
	  ++i;
	}
      else
	{
	  int optc;
	  char **fake_argv = argv + i - 1;

	  /* Initialize getopt_long's internal state.  */
	  optind = 0;

	  if ((optc = getopt_long (argc - (i - 1), fake_argv, "+n:",
				   longopts, (int *) 0)) != EOF)
	    {
	      switch (optc)
		{
		case '?':
		  usage (1);

		case 'n':
		  if (!isinteger (optarg))
		    error (1, 0, _("invalid priority `%s'"), optarg);

		  minusflag = 0;
		  /* FIXME: use xstrtol */
		  adjustment = atoi (optarg);
		  adjustment_given = 1;
		  break;
		}
	    }

	  i += optind - 1;

	  if (optc == EOF)
	    break;
	}
    }

  if (minusflag)
    adjustment = -adjustment;
  if (!adjustment_given)
    adjustment = 10;

  if (i == argc)
    {
      if (adjustment_given)
	{
	  error (0, 0, _("a command must be given with an adjustment"));
	  usage (1);
	}
      /* No command given; print the priority. */
      errno = 0;
      current_priority = GET_PRIORITY ();
      if (current_priority == -1 && errno != 0)
	error (1, errno, _("cannot get priority"));
      printf ("%d\n", current_priority);
      exit (0);
    }

#ifndef NICE_PRIORITY
  errno = 0;
  current_priority = GET_PRIORITY ();
  if (current_priority == -1 && errno != 0)
    error (1, errno, _("cannot get priority"));
  if (setpriority (PRIO_PROCESS, 0, current_priority + adjustment))
#else
  if (nice (adjustment) == -1)
#endif
    error (1, errno, _("cannot set priority"));

  execvp (argv[i], &argv[i]);
  error (errno == ENOENT ? 127 : 126, errno, "%s", argv[i]);
}

/* Return nonzero if S represents a (possibly signed) decimal integer,
   zero if not. */

static int
isinteger (char *s)
{
  if (*s == '-' || *s == '+')
    ++s;
  if (*s == 0)
    return 0;
  while (*s)
    {
      if (!ISDIGIT (*s))
	return 0;
      ++s;
    }
  return 1;
}

static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      printf (_("Usage: %s [OPTION]... [COMMAND [ARG]...]\n"), program_name);
      printf (_("\
Run COMMAND with an adjusted scheduling priority.\n\
With no COMMAND, print the current scheduling priority.  ADJUST is 10\n\
by default.  Range goes from -20 (highest priority) to 19 (lowest).\n\
\n\
  -ADJUST                   increment priority by ADJUST first\n\
  -n, --adjustment=ADJUST   same as -ADJUST\n\
      --help                display this help and exit\n\
      --version             output version information and exit\n"));
      puts (_("\nReport bugs to sh-utils-bugs@gnu.ai.mit.edu"));
    }
  exit (status);
}
