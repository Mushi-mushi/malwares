/*
 
   Author: Timo J. Rinne <tri@iki.fi>
  
   Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>

   Source for ssh_getopt.

   The idea of argv traversal is from the BSD source code.

*/

#define SSHGETOPT_C

#include "sshincludes.h"
#include "sshgetopt.h"

struct SshGetOptDataRec ssh_getopt_default_data = SSH_GETOPT_DATA_INITIALIZER;

void ssh_getopt_init_data(SshGetOptData data)
{
  static struct SshGetOptDataRec def = SSH_GETOPT_DATA_INITIALIZER;
  *data = def;
  return;
}

static int ssh_str_is_number(char *str)
{
  if (!str)
    return 0;
  if ((*str == '-') || (*str == '+'))
    str++;
  if (!(*str))
    return 0;
  for (/*NOTHING*/; *str; str++)
    if ((*str < '0') || (*str > '9'))
      return 0;
  return 1;
}

int ssh_getopt(int argc, char **argv, const char *ostr, SshGetOptData data)
{
  char *optidx;

  if (data == NULL)
    data = &ssh_getopt_default_data;

  if (data->reset || !(*(data->current)))
    {
      data->reset = 0;
      if (data->ind < argc)
        {
          data->current = argv[data->ind];
        }
      else
        {
          data->current = "";
          return -1;
        }
      if (*(data->current) == '-')
        {
          data->val = 1;
        }
      else if ((data->allow_plus) && (*(data->current) == '+'))
        {
          data->val = 0;
        }
      else
        {
          data->current = "";
          return -1;
        }
      if (data->current[1] && (*(++(data->current)) == '-')) 
        {
          /* "--" */
          data->current = "";
          data->ind++;
          return -1;
        }
    }
  if ((data->opt = (int)*((data->current)++)) == ((int)':') ||
      (!(optidx = strchr(ostr, data->opt))))
    {
      if (data->opt == (int)'-')
        {
          /* if '-' is not an option, options, this ends the parsing */
          return -1;
        }
      /* option is illegal */
      if (!(*(data->current)))
        data->ind++;
      if (data->err && (*ostr != ':'))
        {
          fprintf(stderr, "illegal option -- %c\n", data->opt);
        }
      data->miss_arg = 0;
      return '?';
    }
  if (*(++optidx) == ':')
    {
      /* option with argument */
      if (*(data->current))
        {
          /* argument in the same element */
          data->arg = data->current;
          if (ssh_str_is_number(data->arg))
            {
              data->arg_num = 1;
              data->arg_val = atoi((data->arg));
            }
        }
      else if (argc > ++(data->ind))
        {
          /* argument in the next element */
          data->arg = argv[data->ind];
          if (ssh_str_is_number(data->arg))
            {
              data->arg_num = 1;
              data->arg_val = atoi(data->arg);
            }
        }
      else
        {
          /* argument missing */
          data->current = "";
          if (*ostr == ':')
            return ':';
          if (data->err)
            {
              fprintf(stderr, 
                      "option requires an argument -- %c\n", 
                      data->opt);
            }
          data->miss_arg = 1;
          return '?';
        }
      data->current = "";
      data->ind++;
    }
  else
    {                   
      /* no argument */
      data->arg = NULL;
      data->arg_num = 0;
      if (!(*(data->current)))
        data->ind++;
    }
  return data->opt;
}

/* eof (sshgetopt.c) */
