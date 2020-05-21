/*

t-replace.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 21:46:31 1996 ylo
Last modified: Thu Oct 24 22:55:52 1996 ylo

*/

#include "sshincludes.h"

#ifdef macintosh
int errnos[] = { ENOENT, ENOMEM, -1 };
#else
int errnos[] = { EPERM, ENOENT, EINTR, ENOMEM, EEXIST, EINVAL, -1 };
#endif

char data[200];

long counts[1000];

int main(int ac, char **av)
{
  int i, pass;
  int offset, diff, len;
  char byte;
  char *s;

#ifdef macintosh
  printf("Warning: Macintosh does not defined EPERM, EINTR, EEXISTS, EINVAL\n");
#endif
  for (pass = 0; pass < 3; pass++)
    {
      for (i = 0; errnos[i] != -1; i++)
	if (strerror(errnos[i]) == NULL)
	  {
	    printf("errno %d test failed\n", errnos[i]);
	    exit(1);
	  }

      for (offset = 90; offset < 110; offset++)
	for (diff = -20; diff < 20; diff++)
	  for (len = 0; len < 20; len++)
	    {
	      for (i = 0; i < sizeof(data); i++)
		data[i] = i;
	      memmove(data + offset + diff, data + offset, len);
	      for (i = 0; i < sizeof(data); i++)
		{
		  if (i < offset + diff || i >= offset + diff + len)
		    byte = i;
		  else
		    byte = i - diff;
		  if (byte != data[i])
		    {
		      printf("memmove failed offset %d diff %d len %d i %d\n",
			     offset, diff, len, i);
		      exit(1);
		    }
		}
	    }

      s = "testfoo231312";
      remove(s);
      if (remove(s) >= 0)
	{
	  printf("remove failure test failed\n");
	  exit(1);
	}

#ifdef macintosh
      i = open(s, O_CREAT | O_EXCL | O_WRONLY);
#else
      i = open(s, O_CREAT | O_EXCL | O_WRONLY, 0666);
#endif
      if (i < 0)
	{
	  printf("create after remove failed\n");
	  exit(1);
	}
      close(i);
      if (remove(s) < 0)
	{
	  printf("remove after create failed\n");
	  exit(1);
	}

      for (i = 0; i < 1000; i++)
	counts[i] = 0;
      for (i = 0; i < 1000000; i++)
	counts[random() % 1000]++;
      for (i = 0; i < 1000; i++)
	if (counts[i] < 200 || counts[i] > 2000)
	  {
	    printf("random() distribution test indicates probable error!\n");
	    exit(1);
	  }
	 
#if defined(macintosh)
      printf("Warning: Macintosh does not handled putenv or fork\n");
#else
      putenv("SSHTESTVAR1212=12z8");
      if (strcmp(getenv("SSHTESTVAR1212"), "12z8") != 0)
	{
	  printf("putenv test failed\n");
	  exit(1);
	}
      if (fork() == 0)
	{
	  if (strcmp(getenv("SSHTESTVAR1212"), "12z8") == 0)
	    exit(0);
	  else
	    exit(1);
	}
      wait(&i);
      if (!WIFEXITED(i) || WEXITSTATUS(i) != 0)
	{
	  printf("putenv passed over fork test failed\n");
	  exit(1);
	}
#endif

      if (strcasecmp("aaa", "aaa") != 0 || strcasecmp("bbb", "bBb") != 0 ||
	  strcasecmp("aaa", "aAaa") >= 0 || strcasecmp("cccc", "CCC") <= 0 ||
	  strcasecmp("", "") != 0 || strcasecmp("x", "") <= 0 ||
	  strcasecmp("", "x") >= 0)
	{
	  printf("strcasecmp test failed\n");
	  exit(1);
	}

      if (strncasecmp("dff", "FAA", 0) != 0 ||
	  strncasecmp("dff", "dfgs", 1) != 0 ||
	  strncasecmp("zAf", "Zaf", 2) != 0 ||
	  strncasecmp("", "a", 7) >= 0 ||
	  strncasecmp("awasasaasaa", "", 3) <= 0)
	{
	  printf("strncasecmp test failed\n");
	  exit(1);
	}

      for (offset = 70; offset < 130; offset++)
	for (len = 0; len < 30; len++)
	  {
	    for (i = 0; i < sizeof(data); i++)
	      data[i] = i;
	    memset(data + offset, offset, len);
	    for (i = 0; i < sizeof(data); i++)
	      {
		if (i < offset || i >= offset + len)
		  byte = i;
		else
		  byte = offset;
		if (byte != data[i])
		  {
		    printf("memset test failed offset %d len %d i %d\n",
			   offset, len, i);
		    exit(1);
		  }
	      }
	  }
    }
 
  return 0;
}
