/*

  t-psystem.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Nov 24 18:24:07 1997 [mkojo]

  Test the psystem. 

  */

/*
 * $Id: t-psystem.c,v 1.7 1999/05/04 02:20:29 kivinen Exp $
 * $Log: t-psystem.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshasn1.h"
#include "sshpsystem.h"

#define NOT_BEFORE  1
#define NOT_AFTER   2
#define SIZE        3
#define KEY_TYPE    4
#define DN_NAME     5
#define IP_ADDRESS  6
#define DNS_NAME    7
#define VALIDITY    8
#define URI_NAME    9
#define NAMES       10
#define T_LIST      11
#define STR_LIST    12
#define TEST_LIST   13
#define XYZZY       14

Boolean ssh_buf_to_ber_time(unsigned char *buf, size_t buf_len,
                            SshBerTime *ber_time)
{
  char *str = ssh_xmalloc(buf_len + 1);
  memcpy(str, buf, buf_len);
  str[buf_len] = '\0';

  if (sscanf(str, "%4d %2d %2d %2d:%2d",
             &ber_time->year, &ber_time->month,
             &ber_time->day, &ber_time->hour,
             &ber_time->minute) != 5)
    {
      ssh_xfree(str);
      return FALSE;
    }
  ssh_xfree(str);
  return TRUE;
}

void ssh_ber_time_print(SshBerTime *ber_time)
{
  const char *month_table[13] =
  { "n/a", "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec" };
  char *day_postfix = "  ";

  if (ber_time->month < 1 || ber_time->month > 12)
    return;
  
  if ((ber_time->day % 10) == 1)
    day_postfix = "st";
  if ((ber_time->day % 10) == 2)
    day_postfix = "nd";
  if ((ber_time->day % 10) == 3)
    day_postfix = "rd";
  if ((ber_time->day % 10) > 3)
    day_postfix = "th";

#if 0
  ber_time->minute += ber_time->second / 60;
  ber_time->second %= 60;
  ber_time->hour += ber_time->minute / 60;
  ber_time->minute %= 60;
  ber_time->day += ber_time->hour / 24;
  ber_time->hour %= 24;
  ber_time->month += ber_time->day;
  /* Finish this with the calendar computations later... */
#endif
    
  /* Assume GMT. */
  printf("%04d %s %2d%s, %02d:%02d:%02d GMT\n",
         ber_time->year, month_table[ber_time->month],
         ber_time->day, day_postfix,
         ber_time->hour % 24, ber_time->minute % 60, (unsigned int)ber_time->second % 60);
}

SshPSystemVar var_validity[] =
{
  { "NotBefore", NOT_BEFORE, SSH_PSYSTEM_STRING },
  { "NotAfter",  NOT_AFTER,  SSH_PSYSTEM_STRING },
  { NULL}
};

SshPSystemVar var_keygen[] =
{
  { "Size", SIZE, SSH_PSYSTEM_INTEGER },
  { "Type", KEY_TYPE, SSH_PSYSTEM_STRING },
  { NULL}
};

SshPSystemVar var_names[] =
{
  { "DistinguishedName", DN_NAME, SSH_PSYSTEM_LDAP_DN },
  { "IPAddress", IP_ADDRESS, SSH_PSYSTEM_IP },
  { "URI", URI_NAME, SSH_PSYSTEM_STRING },
  { NULL }
};

SshPSystemVar var_test_list[] =
{
  { "integer", T_LIST, SSH_PSYSTEM_INTEGER },
  { "string", STR_LIST, SSH_PSYSTEM_NAME },
  { NULL }
};

SshPSystemVar var_root[] =
{
  { "xyzzy", XYZZY, SSH_PSYSTEM_VOID },
  { "XYZZY", XYZZY, SSH_PSYSTEM_VOID },
  { "Xyzzy", XYZZY, SSH_PSYSTEM_VOID },
  { NULL }
};

typedef struct NamesRec
{
  char *dn;
  char *uri;
  unsigned char *ip;
} Names;

void names_free(void *ctx)
{
  Names *n = ctx;
  ssh_xfree(n->dn);
  ssh_xfree(n->uri);
  ssh_xfree(n->ip);
  ssh_xfree(n);
}

Boolean names_handler(SshPSystemEvent event,
                      unsigned int aptype,
                      void *data, size_t data_len,
                      unsigned int list_level,
                      void *context_in, void **context_out)
{
  Names *n;
  /* We don't support lists. */
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      n = ssh_xmalloc(sizeof(*n));
      n->dn = NULL;
      n->uri = NULL;
      n->ip = NULL;
      *context_out = n;
      return TRUE;
      
    case SSH_PSYSTEM_ERROR:
      names_free(context_in);
      return TRUE;
    
    case SSH_PSYSTEM_FINAL:
      *context_out = context_in;
      return TRUE;
      
    case SSH_PSYSTEM_OBJECT:
      n = context_in;
      switch (aptype)
        {
        case IP_ADDRESS:
          n->ip = data;
          return TRUE;
        case DN_NAME:
          n->dn = data;
          return TRUE;
        case URI_NAME:
          n->uri = data;
          return TRUE;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}

typedef struct ValidityRec
{
  SshBerTime not_before;
  SshBerTime not_after;
} Validity;

void validity_free(void *v)
{
  ssh_xfree(v);
}

Boolean validity_handler(SshPSystemEvent event,
                         unsigned int aptype,
                         void *data, size_t data_len,
                         unsigned int list_level,
                         void *context_in, void **context_out)
{
  Validity *n;
  /* We don't support lists. */
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      n = ssh_xmalloc(sizeof(*n));
      *context_out = n;
      return TRUE;
      
    case SSH_PSYSTEM_ERROR:
      validity_free(context_in);
      return TRUE;
    
    case SSH_PSYSTEM_FINAL:
      *context_out = context_in;
      return TRUE;
      
    case SSH_PSYSTEM_OBJECT:
      n = context_in;
      switch (aptype)
        {
        case NOT_BEFORE:
          return ssh_buf_to_ber_time(data, data_len,
                                     &n->not_before);
        case NOT_AFTER:
          return ssh_buf_to_ber_time(data, data_len,
                                     &n->not_after);
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}

typedef struct {
  SshInt t[10];
  int t_count;
  char *str[10];
  int str_count;
} TestList;

void test_list_free(void *list)
{
  int i;
  TestList *l = list;
  for (i = 0; i < 10; i++)
    ssh_mp_clear(&l->t[i]);
  for (i = 0; i < 10; i++)
    ssh_xfree(l->str[i]);
  ssh_xfree(l);
}

Boolean test_list_handler(SshPSystemEvent event,
                          unsigned int aptype,
                          void *data, size_t data_len,
                          unsigned int list_level,
                          void *context_in, void **context_out)
{
  TestList *l;
  int i;
  if (list_level > 1)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      l = ssh_xmalloc(sizeof(*l));
      for (i = 0; i < 10; i++)
        {
          ssh_mp_init(&l->t[i]);
          l->str[i] = NULL;
        }
      l->t_count = 0;
      l->str_count = 0;
      *context_out = l;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      test_list_free(context_in);
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      *context_out = context_in;
      return TRUE;
    case SSH_PSYSTEM_LIST_OPEN:
      l = context_in;
      if (l->t_count == 0 ||
          l->str_count == 0)
        return TRUE;
      break;
    case SSH_PSYSTEM_LIST_CLOSE:
      l = context_in;
      if (l->t_count != 0 ||
          l->str_count != 0)
        return TRUE;
      break;
    case SSH_PSYSTEM_OBJECT:
      switch (aptype)
        {
        case T_LIST:
          if (list_level == 0)
            break;
          l = context_in;
          if (l->t_count < 10)
            {
              ssh_mp_set(&l->t[l->t_count], (SshInt*)data);
              ssh_mp_clear(data);
              ssh_xfree(data);
              l->t_count++;
              return TRUE;
            }
          ssh_mp_clear(data);
          ssh_xfree(data);
          return FALSE;
        case STR_LIST:
          if (list_level == 0)
            break;
          l = context_in;
          if (l->str_count < 10)
            {
              l->str[l->str_count] = data;
              l->str_count++;
              return TRUE;
            }
          ssh_xfree(data);
          return FALSE;
          break;
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}
                                
SshPSystemEnv env_root[] =
{
  { "Validity", VALIDITY,
    validity_handler,
    NULL, var_validity },
  { "TestList", TEST_LIST,
    test_list_handler,
    NULL, var_test_list },
#if 0
  { "KeyGeneration", KEYGEN,
    keygen_init, keygen_free,
    keygen_final, keygen_add_data,
    NULL, var_keygen },
#endif
  { "Names", NAMES,
    names_handler,
    NULL,  var_names },
  { NULL }
};

Boolean root_handler(SshPSystemEvent event,
                     unsigned int aptype,
                     void *data, size_t data_len,
                     unsigned int list_level,
                     void *context_in, void **context_out)
{
  TestList *l;
  int i;
  if (list_level)
    return FALSE;
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
      *context_out = NULL;
      return TRUE;
    case SSH_PSYSTEM_ERROR:
      return TRUE;
    case SSH_PSYSTEM_FINAL:
      return TRUE;
    case SSH_PSYSTEM_OBJECT:
      switch (aptype)
        {
        case XYZZY:
          if ((random() & 1) == 0)
            printf("Nothing happens.\n");
          else
            printf("Plugh!\n");
          return TRUE;
        case VALIDITY:
          ssh_ber_time_print(&((Validity *)(data))->not_before);
          ssh_ber_time_print(&((Validity *)(data))->not_after);
          validity_free(data);
          return TRUE;
        case NAMES:
          printf("LDAP DN: %s\n", ((Names*)(data))->dn);
          printf("URI: %s\n", ((Names*)(data))->uri);
          if (((Names*)(data))->ip)
            printf("IP: %d.%d.%d.%d\n",
                   (unsigned int)((Names*)(data))->ip[0],
                   (unsigned int)((Names*)(data))->ip[1],
                   (unsigned int)((Names*)(data))->ip[2],
                   (unsigned int)((Names*)(data))->ip[3]);
          names_free(data);
          return TRUE;
        case TEST_LIST:
          printf("Test list:\n");
          l = data;
          printf("t[] = ");
          for (i = 0; i < l->t_count; i++)
            {
              ssh_mp_out_str(NULL, 10, &l->t[i]);
              printf(" ");
            }
          printf("\n");
          for (i = 0; i < l->str_count; i++)
            printf("  %s\n", l->str[i]);
          printf("\n");
          test_list_free(l);
          return TRUE;
        }
    default:
      break;
    }
  return FALSE;
}

SshPSystemEnv root[] =
{
  { "root", 0,
    root_handler,
    env_root, var_root },
  { NULL } 
};

int my_more(void *context, unsigned char **buf, size_t *buf_len)
{
  unsigned char *tmp = ssh_xmalloc(256);
  size_t bytes;
  
  bytes = fread(tmp, 1, 256, (FILE *)context);
  if (bytes == 0)
    {
      ssh_xfree(tmp);
      return 1;
    }
  *buf = tmp;
  *buf_len = bytes;
  return 0;
}

SshPSystemDef def =
{
  root,
  NULL,
  NULL,
  my_more, NULL
};

int main(int argc, char **argv)
{
  FILE *fp;
  void *ret;
  SshPSystemError error;
  char *fn;
  
  fn = (argc == 1) ? "test-file.mc" : argv[1];

  fp = fopen(fn, "r");
  if (fp == NULL)
    {
      printf("No test file \"%s\" to read from.\n", fn);
      exit(1);
    }

  def.more_context = fp;
  ret = ssh_psystem_parse(&def, &error);
  printf("Error: no. %u = \"%s\",\n"
         "position within source: line %u near pos %u\n",
         error.status,
         ssh_psystem_error_msg(error.status), error.line, error.pos);
  fclose(fp);
  return 0;
}
