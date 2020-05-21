/* yes - output a string repeatedly until killed
   Copyright (C) 91, 92, 93, 94, 95, 1996 Free Software Foundation, Inc.

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
#include <sys/types.h>
#include <getopt.h>

#include "system.h"
#include "long-options.h"

/* The name this program was run with. */
char *program_name;

static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      printf (_("Usage: %s [OPTION]... [STRING]...\n"), program_name);
      printf (_("\
Repeatedly output a line with all specified STRING(s), or `y'.\n\
\n\
  --help      display this help and exit\n\
  --version   output version information and exit\n"));
      puts (_("\nReport bugs to sh-utils-bugs@gnu.ai.mit.edu"));
    }
  exit (status);
}

int
main (int argc, char **argv)
{
  program_name = argv[0];
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  parse_long_options (argc, argv, "yes", GNU_PACKAGE, VERSION, usage);

  if (argc == 1)
    while (1)
      puts ("y");

  while (1)
    {
      int i;

      for (i = 1; i < argc; i++)
	{
	  fputs (argv[i], stdout);
	  putchar (i == argc - 1 ? '\n' : ' ');
	}
    }
}
