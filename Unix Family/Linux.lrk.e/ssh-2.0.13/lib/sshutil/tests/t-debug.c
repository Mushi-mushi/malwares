/*

  t-debug.c

  Author: Antti Huima <huima@ssh.fi>

  Copyright (c) 1999 SSH Communications Security, Finland
  All rights reserved.

  Created Fri Jan 22 14:22:30 1999.

  */

#include "sshincludes.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "TestMod"

#define CLR_EOL "%c(27)%C([K)"
#define POSITION(x,y) "%c(27)%C([" #y ";" #x "H)"
#define BGCOLOR(n) "%c(27)%C([4" #n "m)"
#define FGCOLOR(n) "%c(27)%C([3" #n "m)"
#define NORMAL "%c(27)%C([m)"
#define BOLD   "%c(27)%C([1m)"
#define REGION(a,b) "%c(27)%C([" #a ";" #b "r)"
#define CLS "%c(27)%C([H)%c(27)%C([2J)"

static const char *sample_debug_strings[] =
{
  "%m: %M",
  "%f: %M",

  /* Clear screen if we are starting... uses the magic conditional. */

  "%?[*]" CLS "%."
  "%W(79)(2)"
  /* header */
  REGION(1,100)
  POSITION(1,1)
  BGCOLOR(1)
  FGCOLOR(7)
  BOLD
  "%$>(5)o %Dh:%Dm:%Ds        Host '%h'  Pid %p"
  CLR_EOL
  "%N"
  NORMAL

  /* Choose region depending on the debugging level */
  "%?[<(20)]"
  POSITION(1,2)
  BGCOLOR(4) FGCOLOR(7) BOLD "Debug levels 1--19    Uid %u  Euid %u"
  CLR_EOL "%N" NORMAL  
  REGION(3,20)
  POSITION(1,20)
  "%/[<(50)]"
  POSITION(1,21)
  BGCOLOR(6) FGCOLOR(7) BOLD "Debug levels 20--49"
  CLR_EOL "%N" NORMAL  
  REGION(22,40)
  POSITION(1,40)
  "%:"
  POSITION(1,41)
  BGCOLOR(2) FGCOLOR(7) BOLD "Debug levels 50--99"
  CLR_EOL "%N" NORMAL  
  REGION(42,200)
  POSITION(1,200)
  "%."

  "[%l] " BOLD "%m" NORMAL ": "
  "%?[>(49)]%<(50)M%/[<(2)]%c(7)" FGCOLOR(1) BOLD "%M" NORMAL "%S(1000)%:"
  "%M%S(100)"
  "%."
  ,


  NULL
};

int main(int argc, char **argv)
{
  int i, k;
  char buf[1001];

  if (argc > 1)
    {
      i = atoi(argv[1]);
      if (i >= 0)
        {
          k = 0;
          while (k < i && sample_debug_strings[k] != NULL)
            k++;
          if (sample_debug_strings[k] != NULL)
            {
              ssh_debug_set_format_string(sample_debug_strings[k],
                                          TRUE);
              fprintf(stderr, "Using the format string '%s'\n",
                      sample_debug_strings[k]);
            }
        }
    }
  else
    {
      fprintf(stderr, "Usage: %s n, where n is an integer between 0 and 2.\n",
              argv[0]);

      fprintf(stderr, "n is used to choose a debug "
              "format string to be used.\n");
      
      fprintf(stderr, "The following strings can be chosen from:\n");

      for (i = 0; sample_debug_strings[i] != NULL; i++)
        {
          fprintf(stderr, "(n = %d) '%s'\n", i, sample_debug_strings[i]);
        }

      /* Return success in the case that someone runs this as 
         a unit test. */
      exit(0);        
    }

  ssh_debug_set_global_level(99);

  for (i = 0; i < 10000; i++)
    {
      for (k = 0; k < 1000; k++)
        {
          buf[k] = random() % 50 + 'A';
          if ((random() % 10) == 0)
            buf[k] = ' ';
          if ((random() % 500) == 0)
            buf[k] = 0;
        }
      buf[1000] = 0;
      SSH_DEBUG(random() % 100, ("Sample message: %s", buf));
    }
  exit(0);
}
