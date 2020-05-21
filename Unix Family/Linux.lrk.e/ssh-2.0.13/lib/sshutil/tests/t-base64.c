/*

  t-base64.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
                   All rights reserved.

  Created: Wed Oct 22 17:23:38 1997 [mkojo]

  Test program which knows how to convert base64 into and onto.
  
*/

/*
 * $Id: t-base64.c,v 1.5 1999/03/15 15:24:35 tri Exp $
 * $Log: t-base64.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbase64.h"
#include "sshfileio.h"

void usage(void)
{
  printf("t-base64 [options] -from filename -to filename\n"
         "options: \n"
         " -base64     denotes that the input is in base 64.\n"
         "             Default is from binary to base64.\n");
  exit(0);
}

int main(int ac, char *av[])
{
  int pos, base = 256;
  char *tofile = NULL, *fromfile = NULL;
  unsigned char *buf;
  size_t buf_len;
  
  for (pos = 1; pos < ac; pos++)
    {
      if (strcmp("-to", av[pos]) == 0)
        {
          tofile = av[pos + 1];
          pos++;
          continue;
        }
      if (strcmp("-from", av[pos]) == 0)
        {
          fromfile = av[pos + 1];
          pos++;
          continue;
        }
      if (strcmp("-base64", av[pos]) == 0)
        {
          base = 64;
          continue;
        }
      if (strcmp("-h", av[pos]) == 0 ||
          strcmp("--help", av[pos]) == 0)
        {
          usage();
        }
      printf("Unknown option '%s'.\n", av[pos]);
      exit(1);
    }

  if (tofile == NULL || fromfile == NULL)
    {
      usage();
    }

  if (base == 256)
    {
      if (!ssh_read_file(fromfile, &buf, &buf_len))
        ssh_fatal("Could not read file %s", fromfile);
      if (!ssh_write_file_base64(tofile, "", "", buf, buf_len))
        ssh_fatal("Could not write base64 file %s", tofile);
      ssh_xfree(buf);
    }
  else
    {
      if (base == 64)
        {
          if (!ssh_read_file_base64(fromfile, &buf, &buf_len))
            ssh_fatal("Could not read base64 file %s", fromfile);
          if (!ssh_write_file(tofile, buf, buf_len))
            ssh_fatal("Could not write file %s", tofile);
          ssh_xfree(buf);
        }
      else
        {
          usage();
        }
    }
  return 0;
}
