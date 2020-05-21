
/* Version 0.0095

  It now gladly understand the following:
   -a -all -c --time=ctime --time=status -d -f -r -t --sort=time
   -u --time=atime --time=access --time=use -A --almost-all -B --ignore-backups
   -L -R -S --sort=size -U --sort=none -X --sort=extension -I
   -T -w -I
   -l --format=long --format=verbose

  The following 3 flags we CHOOSE not to implement:
   -b -q -O
*/

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "urk.h"

#define max 32768
typedef char * charp;

char *progname_me;
char *prog_ptr;
char progname[256];
char progname_with_l[260];
int no_ls_filters;
int fd_error;

/*=============================================================================
 Takes in a number of separate strings,
 join them to form the (argc,argv) pair

 Note: it trims the final cr and/or lf  from the incoming strings
=============================================================================*/

struct merger {
 int argc;
 int midpoint;
 char* ptr;
 int save_argc;
 int save_midpoint;
 char* save_ptr;
 char buf[max];
 charp argv[max];
 };

struct merger mainargs;
struct merger moreargs;

void merger_save(struct merger* m) {
   m->save_argc = m->argc;
   m->save_midpoint = m->midpoint;
   m->save_ptr = m->ptr;
   }
   
void merger_restore(struct merger* m) {
   m->argc = m->save_argc;
   m->midpoint = m->save_midpoint;
   m->ptr = m->save_ptr;
   }

void merger_reset(struct merger* m) {
   m->argc=0;
   m->midpoint=0;
   m->ptr=m->buf;
   m->argv[0]=0;
   }

void merger_add(struct merger* m, char* newstr) {
   m->argv[m->argc++] = m->argv[m->midpoint];
   m->argv[m->argc] = 0;
   m->argv[m->midpoint++] = m->ptr;
   while(*newstr!=0 && *newstr!='\r' && *newstr!='\n')
       { *m->ptr++ = *newstr++; }
   *m->ptr++ = 0;
   }

void merger_add_flag(struct merger* m, char flag) {
   m->argv[m->argc++] = m->argv[m->midpoint];
   m->argv[m->argc] = 0;
   m->argv[m->midpoint++] = m->ptr;
   *m->ptr++ = '-';
   *m->ptr++ = flag;
   *m->ptr++ = 0;
   }

void merger_add2(struct merger* m, char* newstr) {
   m->argv[m->argc++] = m->ptr;
   m->argv[m->argc] = 0;
   while(*newstr!=0 && *newstr!='\r' && *newstr!='\n')
       { *m->ptr++ = *newstr++; }
   *m->ptr++ = 0;
   }

void merger_dump(struct merger* m) {
   /* Dumps the merger_argv array */
   int i;
   for(i=0; m->argv[i]; i++) {
     printf("[%d] = %p \"%s\"\n", i, m->argv[i], m->argv[i]);
     fflush(stdout);
     }
   }

/*===========================================================================*/

int execute(char* name, char** argv) {
    int stat_loc;
    pid_t zp;
    zp=fork();
    if (!zp)
        {
         execv(name,argv);
         exit(0);
        }
    else
        {
         waitpid(zp,&stat_loc,0);
	 return stat_loc >> 8;
	}
    }

int ban(char* name) {
   int i;
   for(i=0; i<no_ls_filters+1; i++)
     if (strstr(name,f_ptr[i])) return 1;
   return 0;
   }

char result_buffer[150];
char result_buffer_2[150];
char original_dir[1024];

int trim_colon(char* z) {
  while(*z) {
    if (*z==':') {
       z++;
       if (*z==0 || *z=='\r' || *z=='\n') { *(z-1)=0; return 1; }
       continue;
       }
    z++;
    }
  return 0;
  }

int is_directory(char* somename) {
    DIR* z=opendir(somename);
    if (z)
        { closedir(z); return 1; }
    else
        return 0;
    }


/* Open, Read, then Close the pipe */
void process2(int is_long) {

  FILE* result;
  FILE* result2;  /* for the '-l' result */
  int pipe_empty;
  int once_already, got_files=0;

  /* Open the pipe */
  dup2(fd_error, 2);
  result = popen_r(progname, moreargs.argv, NULL);
  close(2);

  /* Clear the pipe */
  pipe_empty = 0;

  /* Store the MERGER's current state */
  merger_save(&mainargs);

  /* Initially, nothing has been displayed yet */
  once_already = 0;

  /* Loops to process EACH directory */
  while(!pipe_empty) {

      /* Restore the MERGER's current state */
      merger_restore(&mainargs);
     
      /* Read the 1st line */
      if (!fgets(result_buffer, sizeof(result_buffer), result))
         break;
      if (*result_buffer==0 || *result_buffer=='\r' || *result_buffer=='\n')
	 continue;

      /* Has anything been displayed yet? */
      if (once_already) putchar('\n');

      /* Is this a directory heading?  (ie. "xxx:" )  */
      if (trim_colon(result_buffer))
         {
	   chdir(result_buffer);
	   printf("%s:\n", result_buffer);
	   once_already = 1;
           got_files = 0;
	 }
      else
         {
	   if (!ban(result_buffer))
	    {
             merger_add(&mainargs, result_buffer);
	     got_files = 1;
	    }
	 }

      /* Retrieve the size */
      result2 = popen(progname_with_l, "r");
      if (!fgets(result_buffer_2, sizeof(result_buffer_2), result2))
         { result_buffer_2[0]=0; }
      pclose(result2);

      /* Read the rest of this directory, one by one */
      while(!feof(result)) {
          if (!fgets(result_buffer, sizeof(result_buffer), result))
              { pipe_empty++; break; }
	  if (*result_buffer==0 || *result_buffer=='\r' || *result_buffer=='\n')
	      break;
	  if (ban(result_buffer)) continue;
          got_files=1;
	  merger_add(&mainargs, result_buffer);
          }

      /* If it's using the long format, then display the "total" info */
      if (is_long)
	 if (*result_buffer_2)
	    printf("%s",result_buffer_2);

      /* If got files, then display them using the CORRECT flags  */
      if (got_files) {
          once_already=1;
          fflush(stdout); execute(progname, mainargs.argv); fflush(stdout);	  
	  }

      /* Return to the original directory */
      chdir(original_dir);
      }
     
  /* Close the pipe */
  pclose(result);
  }

/* Prepare the arguments needed for opening the pipe */
void process(char** argv) {

  int i;
  int flag_done;
  int is_long;
  int just_one_file;
   /* -1:no file yet  -2:more than 1 file  >=0: file's index */
  
  /* Get original current directory */
  getcwd(original_dir, sizeof(original_dir));
  
  /* Copies the executable name */
  merger_reset(&mainargs);
  merger_reset(&moreargs);
  merger_add(&mainargs, progname_me);
  merger_add(&moreargs, progname_me);

  /* Copies all FLAGS and FILES */
  flag_done=0;
  just_one_file=-1;
  is_long=0;
  for(i=1; argv[i]; i++) {

      /* If it is a file... */
      if (flag_done || argv[i][0]!='-') {
         if (just_one_file == -1)
            { just_one_file = i; continue; }
         if (just_one_file >= 0)
            { merger_add2(&moreargs, argv[just_one_file]); just_one_file=-2; }
         merger_add2(&moreargs, argv[i]);
	 continue;
	 }
	 
      /* If it is an old-style flag... */
      if (argv[i][1]!='-') {
         char* flagptr;
	 int this_done=0;
	 for(flagptr = argv[i]+1; *flagptr && !this_done; flagptr++) {
	    switch(*flagptr) {
	       case 'l':
	          is_long=1; merger_add(&mainargs, "-l"); break;
	       case 'a': case 'c': case 'd': case 'f': case 'r': case 't': case 'u':
	       case 'A': case 'B': case 'L': case 'R': case 'S': case 'U': case 'X':
		  merger_add_flag(&mainargs, *flagptr);
	          merger_add_flag(&moreargs, *flagptr);
		  break;
	       case 'I':
	          if (flagptr[1]==0) {
		     merger_add(&mainargs, "-I"); merger_add(&mainargs, argv[i+1]);
	             merger_add(&moreargs, "-I"); merger_add(&moreargs, argv[i++]);
		     this_done=1; break;
		     }
		   *(flagptr-1)='-';
	           merger_add(&mainargs, flagptr-1);
		   merger_add(&moreargs, flagptr-1);
		   this_done=1; break;
	       case 'w': case 'T':
	          if (flagptr[1]==0) {
		     merger_add_flag(&mainargs, *flagptr);
		     merger_add(&mainargs, argv[i+1]);
		     i++;
		     this_done=1; break;
		     }
		   *(flagptr-1)='-';
		   merger_add(&mainargs, flagptr-1);
		   this_done=1; break;
	       default:
	          merger_add_flag(&mainargs, *flagptr);
	       }
	    }
	 continue;
	 }

      /* So, it is a new-style flag... */
      if (argv[i][2]==0)
         { flag_done=1; continue; }
      if (!strcmp(argv[i],"--format=long") || !strcmp(argv[i],"--format=verbose"))
	 { is_long=1; merger_add(&mainargs, argv[i]); continue; }
      if (!strcmp(argv[i],"--all") ||          
	  strstr(argv[i],"--time=") ||
          strstr(argv[i],"--sort=") ||
          !strcmp(argv[i],"--almost-all") ||
          !strcmp(argv[i],"--ignore-backups") )
	 { merger_add(&mainargs, argv[i]); merger_add(&moreargs, argv[i]); continue; }
      merger_add(&mainargs, argv[i]); continue;
      }

  /* Append the additional FLAGS for the pipe */
  merger_add(&moreargs, "-1");
  merger_add(&moreargs, "--");

  /* Append the additional FLAGS for the parent call to ls */
  merger_add(&mainargs, "-d");
  merger_add(&mainargs, "--");

  /* Special Case: If there is exactly 1 name, check if it is dir or not */
  if (just_one_file >= 0) {
     if (is_directory(argv[just_one_file])) {
         chdir(argv[just_one_file]);
	 strcpy(original_dir, argv[just_one_file]);
	 }
     else {
         merger_add2(&moreargs, argv[just_one_file]);
	 } 
     }

  /* Open, Read, then Close the Pipe */
  process2(is_long);
  }
  

char main_buf[80];
int main(int argc, char** argv) {

  /* Read a configuration file to determine the "ban" list */
  char *ls_filter_ptr;
  char ls_filter[256];
  char *with_l=" -l";

  /* Save the error descriptor */
  fd_error = dup(2);
  
  /* Read the location of ls from the config file */
  prog_ptr = file(conf_file,file_section,ls_location);
#ifdef URK_DEFAULT
  if((prog_ptr == NULL) || (open(prog_ptr,O_RDONLY) == -1)) { prog_ptr = ls_loc_def; }
#endif
  strcpy(progname,prog_ptr);
  strcpy(progname_with_l,prog_ptr);

  ls_filter_ptr = file(conf_file,file_section,file_filters);
#ifdef URK_DEFAULT
  if(ls_filter_ptr == NULL) { ls_filter_ptr = file_fil_def; }
#endif
  strcpy(ls_filter,ls_filter_ptr);
  no_ls_filters = count_filter(ls_filter);
  
  strcat(progname_with_l,with_l);

  /* Name of this binary */  
  progname_me = argv[0];
  
  /* Do it */
  process(argv);
  return 0;
}
