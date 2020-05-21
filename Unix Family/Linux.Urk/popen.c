#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

FILE* popen_r(char* name_to_use, char** argv, pid_t* return_pid)
{
  int the_pipes[2];
  pid_t child_pid;
  
  /* If return_pid not NULL, then use it to store pid. */
  /*  else, put the pid on the stack, which will be destroyed at exit.*/
  if (return_pid==NULL) return_pid=&child_pid;

  /* Generate a pipe with 2 descriptors: [0] for reading, [1] for writing */  
  pipe(the_pipes);

  if ((*return_pid=fork())==0)
  {
    dup2(the_pipes[1],STDOUT_FILENO);
    execvp(name_to_use, argv);
    _exit(0);
    return 0;
  }
  else
  {
    close(the_pipes[1]);
    return fdopen(the_pipes[0], "r");
  }
}
