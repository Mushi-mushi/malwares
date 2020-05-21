/*

t-malloc.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 22:59:37 1996 ylo
Last modified: 01:53 Apr 21 1999 kivinen

*/

#include "sshincludes.h"

char *p[10000];

int main(int ac, char **av)
{
  int pass;
  int i, j, len;

  for (pass = 0; pass < 10; pass++)
    {
      for (i = 0; i < 10000; i++)
        {
          len = random() % 1000;
          if (random() % 256 == 0)
            len += random() % 65000;
          if (random() % 2)
            p[i] = ssh_xmalloc(len);
          else
            if (random() % 2)
              p[i] = ssh_xcalloc(len, 1);
            else
              p[i] = ssh_xcalloc(1, len);
          if (p[i] == NULL)
            {
              printf("ssh_xmalloc %d bytes failed\n", len);
              exit(1);
            }
          memset(p[i], i, len);
        }

      for (i = 0; i < 10000; i++)
        {
          p[i] = ssh_xrealloc(p[i], random() % 2000);
          if (p[i] == NULL)
            {
              printf("ssh_xrealloc failed\n");
              exit(1);
            }
        }

      for (i = 0; i < 1000; i++)
        {
          if (p[i])
            {
              ssh_xfree(p[i]);
              p[i] = NULL;
            }
          j = random() % 10000;
          if (p[j])
            {
              ssh_xfree(p[j]);
              p[j] = NULL;
            }
        }

      for (i = 0; i < 1000; i++)
        p[i] = ssh_xmalloc(random() % 1000);

      for (i = 0; i < 10000; i++)
        if (p[i])
          ssh_xfree(p[i]);

    }

#ifdef SSH_DEBUG_MALLOC
  {
    pid_t pid;
    int i;
    unsigned char *r, *q;
    size_t size;

    for(i = 0; i < 210; i++)
      {
        pid = fork();
        if (pid == 0)
          {
            switch (i % 10)
              {
              case 0: size = 32; break;
              case 1: size = 31; break;
              case 2: size = 30; break;
              case 3: size = 29; break;
              case 4: size = 28; break;
              case 5: size = 27; break;
              case 6: size = 26; break;
              case 7: size = 25; break;
              case 8: size = 65536; break;
              case 9: size = 65534; break;
              }
            switch (i / 10)
              {
                /* Test overwrite checks in free */
              case 0:
                r = ssh_xmalloc(size);
                r[-1] = 23;
                ssh_xfree(r);
                break;
              case 1:
                r = ssh_xmalloc(size);
                r[size] = 42;
                ssh_xfree(r);
                break;
                /* Test overwrite checks in realloc */
              case 2:
                r = ssh_xmalloc(size);
                r[-1] = 23;
                ssh_xrealloc(r, size * 2);
                break;
              case 3:
                r = ssh_xmalloc(size);
                r[size] = 23;
                ssh_xrealloc(r, size * 2);
                break;
                /* Test overwrite checks in free after realloc */
              case 4:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[-1] = 23;
                ssh_xfree(r);
                break;
              case 5:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[size * 2] = 23;
                ssh_xfree(r);
                break;
                /* Test overwrite checks in realloc after realloc */
              case 6:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[-1] = 23;
                ssh_xrealloc(r, size);
                break;
              case 7:
                r = ssh_xmalloc(size);
                r = ssh_xrealloc(r, size * 2);
                r[size * 2] = 23;
                ssh_xrealloc(r, size);
                break;
                /* Test double free */
              case 8:
                r = ssh_xmalloc(size);
                ssh_xfree(r);
                ssh_xfree(r);
                break;
                /* Test free for previous block assuming realloc moved block */
              case 9:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                ssh_xfree(r);
                break;
                /* Test overwrite checks in free after realloc, assuming
                   realloc moved block */
              case 10:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[-1] = 23;
                ssh_xfree(q);
                break;
              case 11:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[size * 10] = 23;
                ssh_xfree(q);
                break;
                /* Test overwrite checks in realloc after realloc, assuming
                   realloc moved block */
              case 12:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[-1] = 23;
                ssh_xrealloc(q, size);
                break;
              case 13:
                r = ssh_xmalloc(size);
                ssh_xmalloc(size); /* This should cause realloc to move the
                                      block */
                q = ssh_xrealloc(r, size * 10);
                if (q == r)
                  ssh_fatal("Realloc did not move the block");
                q[size * 10] = 23;
                ssh_xrealloc(q, size);
                break;
                /* Reallocating freed block */
              case 14:
                r = ssh_xmalloc(size);
                ssh_xfree(r);
                ssh_xrealloc(r, size * 2);
                break;
                /* Freeing unknown block */
              case 15:
                r = ssh_xmalloc(size);
                ssh_xfree(r + 4);
                break;
                /* Freeing unknown stack block */
              case 16:
                ssh_xfree(&r);
                break;
                /* Freeing unknown bss block */
              case 17:
                ssh_xfree(p);
                break;
                /* Reallocating unknown block */
              case 18:
                r = ssh_xmalloc(size);
                ssh_xrealloc(r + 4, size);
                break;
                /* Reallocating unknown stack block */
              case 19:
                ssh_xrealloc(&r, size);
                break;
                /* Reallocating unknown bss block */
              case 20:
                ssh_xrealloc(p, size);
                break;
              }
            exit(0);
          }
        else
          {
            int status;
            
            if (wait(&status) != pid)
              {
                ssh_fatal("Wrong pid returned by wait");
              }
            if (WIFSIGNALED(status))
              {
                ssh_fatal("Child test %d exited with signal %d",
                          i, WTERMSIG(status));
              }
            if (WEXITSTATUS(status) == 0)
              {
                ssh_fatal("Child test %d exited with status %d, should have failed",
                          i, WEXITSTATUS(status));
              }
          }
      }
  }
#endif /* SSH_DEBUG_MALLOC */
  return 0;
}
