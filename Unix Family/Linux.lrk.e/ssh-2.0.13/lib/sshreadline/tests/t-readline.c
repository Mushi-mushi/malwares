/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshreadline test
 *        $Source: /ssh/CVS/src/lib/sshreadline/tests/t-readline.c,v $
 *        $Author: tmo $
 *
 *        Creation          : 06:45 Mar 14 1997 kivinen
 *        Last Modification : 06:57 Mar 14 1997 kivinen
 *        Last check in     : $Date: 1999/03/17 08:52:14 $
 *        Revision number   : $Revision: 1.3 $
 *        State             : $State: Exp $
 *        Version           : 1.4
 *
 *        Description       : Readline library test program
 *
 *
 *        $Log: t-readline.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshreadline.h"
#include "sshunixeloop.h"
#include "sshgetopt.h"

void cb(int fd, char *line)
{
  fprintf(stderr, "\nline = %s\n", line);
}
int main(int argc, char **argv)
{
  unsigned char *line = NULL, *prompt = "*> ";
  int opt;
  Boolean eloop = FALSE;

  while ((opt = ssh_getopt(argc, argv, "p:i:e", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'p': prompt = ssh_optarg; break;
        case 'i': line = ssh_xstrdup(ssh_optarg); break;
        case 'e': eloop = TRUE; break;
        default:
          fprintf(stderr, "%s: usage %s [-e] [-p prompt] [-i initial-data]\n",
                  argv[0], argv[0]);
          exit(1);
        }
    }

  if (eloop)
    {
      ssh_event_loop_initialize();
      ssh_readline_eloop(prompt, line, 0, cb);
      ssh_event_loop_run();
      ssh_event_loop_uninitialize();
    }
  else
    {
      ssh_readline(prompt, &line, 0);
      fprintf(stderr, "\nline = %s\n", line);      
    }
  return 0;
}
