/*

  t-dsprintf.c

  Author:
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
*/

#include "sshincludes.h"
#include "sshdsprintf.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "TestSshDSprintf"

void test_debug(const char *msg, void *context)
{
  Boolean verbose = *(Boolean *)context;

  if (verbose)
    fprintf(stderr, "t-dsprintf: %s", msg);
}

int main(int argc, char **argv)
{
  char *buffer;
  char *buffer2;
  int return_value;
  Boolean verbose = FALSE;
  
  
  while (1)
    {
      int option;
      ssh_opterr = 0;
      ssh_optallowplus = 1;
      
      option = ssh_getopt(argc, argv, "d:v", NULL);
      
      if (option == -1)
        break;

      switch (option)
        {
        case 'd':
          ssh_debug_set_global_level(atoi(ssh_optarg));
          verbose = TRUE;
          break;
        case 'v':
          verbose = TRUE;
          break;
        }  
    }

  ssh_debug_register_callbacks(NULL, test_debug, test_debug, &verbose);

  fprintf(stderr, "Running test for ssh_dsprintf, use -v for verbose "
                  "output, and -d <level> to set debug level.");
  
  return_value =
    ssh_dsprintf(&buffer,
                 "This is a very long %s to test %s\'s capabilities;\n"
                 "this test was very easy to implement;\n"
                 "%s is much more demanding. You can see that\n"
                 "I\'m a bit bored at the moment, so let\'s add some\n"
                 "exitement:\n"
                 "Here\'s the original string: \n%s%s%s\n"
                 "It\'s length was %s.\n", "string", "ssh_dsprintf",
                 "ssh2", "<quote>\n", "%s\n", "</quote>",
                 "%d");
  
  SSH_DEBUG(0, ("first string's length is %d. (ssh_dsprintf wrote " \
                "%d characters.)",\
                strlen(buffer), return_value));

  if (strlen(buffer) != return_value)
    {
      SSH_DEBUG(0, ("buffer length differ's from characters written. " \
                    "(buffer len:%d, return value: %d",
                    strlen(buffer), return_value));
      return(1);
    }
  
  return_value = ssh_dsprintf(&buffer2, buffer, buffer, strlen(buffer));
  
  SSH_DEBUG(0, ("second string's length is %d. (ssh_dsprintf wrote " \
                "%d characters.)",\
                strlen(buffer2), return_value));

  if (strlen(buffer2) != return_value)
    {
      SSH_DEBUG(0, ("buffer2 length differ's from characters written. " \
                    "(buffer2 len:%d, return value: %d",
                    strlen(buffer2), return_value));
      return(1);
    }

  if (verbose)
    fprintf(stderr, "%s", buffer2);

  ssh_xfree(buffer);
  ssh_xfree(buffer2);

  return(0);
}
