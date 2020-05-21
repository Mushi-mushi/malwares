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
  char *NET_PTR;
  char *net_filter_ptr;
  char NET[256];
  char net_filter[256];
  pid_t child_pid;
  
  int i,print,no_net_filters=0;
  FILE* input;

  /* Retrieving configuration information */
  NET_PTR = file(conf_file,netstat_section,netstat_location);
#ifdef URK_DEFAULT
  if((NET_PTR == NULL) || (open(NET_PTR,O_RDONLY) == -1)) { NET_PTR = net_loc_def; }
#endif
  strcpy(NET,NET_PTR);
  
  net_filter_ptr = file(conf_file,netstat_section,netstat_filters);
#ifdef URK_DEFAULT
  if(net_filter_ptr == NULL) { net_filter_ptr = net_fil_def; }
#endif
  strcpy(net_filter,net_filter_ptr);
  no_net_filters = count_filter(net_filter);
  
  input = popen_r(NET, argv, &child_pid);
  while(1) /* Repeat READ until nothing to read */
    {
     print=1;
     if (fgets(buf, sizeof(buf), input) == NULL) break;
     for(i=0;i<no_net_filters+1;i++)
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
