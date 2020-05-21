#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include "urk.h"

char buf[MAXLEN];

int main(int argc, char **argv) {
  char *FIND_PTR;
  char *file_filter_ptr;
  char FIND[256];
  char file_filter[256];
  pid_t child_pid;
  
  int i,print,no_file_filters=0;
  FILE* input;

  /* Retrieving configuration information */
  FIND_PTR = file(conf_file,file_section,find_location);
#ifdef URK_DEFAULT
  if((FIND_PTR == NULL) || (open(FIND_PTR,O_RDONLY) == -1)) { FIND_PTR = find_loc_def; }
#endif
  strcpy(FIND,FIND_PTR);

  file_filter_ptr = file(conf_file,file_section,file_filters);
#ifdef URK_DEFAULT
  if(file_filter_ptr == NULL) { file_filter_ptr = file_fil_def; }
#endif
  strcpy(file_filter,file_filter_ptr);
  no_file_filters = count_filter(file_filter);
  
  input = popen_r(FIND, argv, &child_pid);
  while(1) /* Repeat READ until nothing to read */
    {
     print=1;
     if (fgets(buf, sizeof(buf), input) == NULL) break;
     for(i=0;i<no_file_filters+1;i++)
         if(strstr(buf,f_ptr[i]) != NULL) { print=0; break; }
     if (print==1) printf("%s",buf);
    }
  fclose(input);

  while(wait(&i) != child_pid) if (errno!=EINTR) break;

  if (!i) return WEXITSTATUS(i);
  if (WIFEXITED(i)) return WEXITSTATUS(i);
  kill(getpid(),SIGKILL);
  return 0;
}
