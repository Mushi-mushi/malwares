#define _XOPEN_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <stdlib.h>



#define PASSFILE "./.rkpass" /* change PASSFILE to what you want but you
			        must define PASSFILE in rkit.c equally */


char saltgen(time_t rtime)
{
  int element = 0;
  char choices[65] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

  srand(rtime);
  element = (int) (65.0*rand()/(RAND_MAX+1.0));

  return choices[element];
}

void main(int argc, char *argv[])
{
  time_t rtime = 0;
  char pass[14] = "\0";
  char temp[9] = "\0";
  char salt[3]  = "\0";
  int filefd = -1;

  rtime = time((time_t *)rtime);

  salt[0] = saltgen(rtime);
  salt[1] = saltgen(rtime-3);
  salt[2] = '\0';

  if((filefd=open(PASSFILE, O_WRONLY|O_TRUNC|O_CREAT, S_IREAD|S_IWRITE)) > 0) {
    printf("Enter a new password [1-8 characters]\n");
    strncpy(temp, getpass("Password: "), (sizeof(temp)-1));
    strncpy(pass, crypt(temp, salt), (sizeof(pass)-1));

    temp[strlen(temp) + 1] = '\0';
    pass[strlen(pass) + 1] = '\0';

    if( write(filefd, pass, strlen(pass)) >= 0) {
      printf("Saved new password to file: %s\n", PASSFILE);
      close(filefd);
   }
    else {
      printf("Writing to file: %s failed! Exiting...\n", PASSFILE);
      close(filefd);
    }
  }
  else {
    printf("Opening of file: %s failed! Exiting...\n", PASSFILE);
    exit(0);
  }
}
