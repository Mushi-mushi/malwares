/*

  sftp2.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  A ssh-sftp client 
 
 */

#include "ssh2includes.h"
#include "sshreadline.h"
#include "sshtimeouts.h"
#include "sshtcp.h"
#include "sshunixfdstream.h"
#include "sshbuffer.h"
#include "sshconfig.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshfilexfer.h"
#include "sshstreampair.h"
#include "sshunixpipestream.h"

#define SSH_DEBUG_MODULE "SshSftp"

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

/* saved program name */
const char *av0;

/* buffer size for put/get */
#define SFTP_BUF_SIZE 0x4000

/* sftp context */

typedef struct SftpCallbackCtxRec *SftpCallbackCtx;

typedef struct SftpCipherNameRec {
  char *name;
  struct SftpCipherNameRec *next;
} *SftpCipherName;

typedef struct 
{
  Boolean connected;                   /* status */
  char *remote_host;
  char *remote_port;
  char *remote_user;
  Boolean prompt;
  Boolean verbose;
  Boolean globbing;
  Boolean bell;
  Boolean quiet;
  Boolean hash;
  Boolean alive;
  Boolean sort;
  Boolean page;  
  Boolean debug;
  char *debug_level;
  long timeout;
  
  /* Our current globbing mask, or NULL, which is effectively "*" */
  char *mask;
  
  /* This represents our connection to the remote end */
  SshFileClient remote_client; 
  char *remote_path;
  
  /* pid of the child process, which exec's ssh2 */
  pid_t child_pid; 

  /* Streams */
  SshStream local_server_stream;
  SshStream local_client_stream;
  SshStream remote_client_stream;
  
  /* Our local client and server */ 
  SshFileClient local_client;
  SshFileServer local_server;
  char *local_path;
    
  Boolean fired;                       /* TRUE: timeout, FALSE: ok */
  Boolean called;                      /* TRUE: we have a result */
  
  /* Return values from various types of callbacks */
  
  SshFileClientError error;            /* Error status (set by all calls) */
  SshFileHandle handle;                /* File handle */  
  const unsigned char *data;           /* Data */
  size_t len;                          /* Length of data */  
  char *name;                          /* File name */
  char *long_name;                     /* "long" file name */
  SshFileAttributes attributes;        /* File attributes */

  /* Ssh client option stuff */

  char *ssh_path;
  SftpCipherName cipher_list;
  SftpCipherName cipher_list_last;
  
} *Sftp;

/* forward declarations */

void sftp_free(Sftp sftp);
int sftp_pwd(int argc, char **argv, Sftp sftp);
int sftp_disconnect(int argc, char **argv, Sftp sftp);
             

/*
 *  A context given to callback functions; the callback should free this
 *  context and terminate immediately the timeout has fired.
 */
 
/* A timeout callback */

void sftp_timeout_callback(void *context)
{
  Sftp sftp;  
  
  sftp = (Sftp) context;
  sftp->fired = TRUE;  
  
  ssh_event_loop_abort();
}

/* A file status callback */

void sftp_file_status_callback(SshFileClientError error, void *context)
{
  Sftp sftp; 
  
  sftp = (Sftp) context;
  if (sftp->fired)
    return;  
  sftp->error = error;
  sftp->fired = FALSE;  
  sftp->called = TRUE;
  
  ssh_event_loop_abort();  
}

/* A file handle callback */

void sftp_file_handle_callback(SshFileClientError error, 
                               SshFileHandle handle, void *context)
{
  Sftp sftp;
  
  sftp = (Sftp) context;  
  if (sftp->fired)
    return;  
  sftp->error = error;
  sftp->handle = handle;
  sftp->fired = FALSE;
  sftp->called = TRUE;
  
  ssh_event_loop_abort();
}
 
/* A data return callback */

void sftp_file_data_callback(SshFileClientError error, 
                             const unsigned char *data,
                             size_t len, void *context)
{
  Sftp sftp;

  sftp = (Sftp) context;  
  if (sftp->fired)
    return;  
  sftp->error = error;
  sftp->data = data;
  sftp->len = len;  
  sftp->fired = FALSE;
  sftp->called = TRUE;
  
  ssh_event_loop_abort();
}

/* File name return callback */

void sftp_file_name_callback(SshFileClientError error, 
                             const char *name, 
                             const char *long_name,
                             SshFileAttributes attributes,
                             void *context)
{
  Sftp sftp;
  
  sftp = (Sftp) context;
  if (sftp->fired)
    return;  
  sftp->error = error;
  sftp->name = name ? ssh_xstrdup(name) : NULL;
  sftp->long_name = long_name ? ssh_xstrdup(long_name) : NULL;
  sftp->attributes = attributes ? ssh_file_attributes_dup(attributes) : NULL;
  sftp->fired = FALSE;
  sftp->called = TRUE;
  
  ssh_event_loop_abort();
}

/* File attribute callback */

void sftp_file_attribute_callback(SshFileClientError error, 
                                  SshFileAttributes attributes,
                                  void *context)
{
  Sftp sftp;
  
  sftp = (Sftp) context;
  if (sftp->fired)
    return;  
  sftp->error = error;
  sftp->attributes = ssh_file_attributes_dup(attributes);
  sftp->fired = FALSE;
  sftp->called = TRUE;
  
  ssh_event_loop_abort();
}

/* Check for a timeout or an error */

Boolean sftp_error(Sftp sftp)
{
  if (sftp->fired)
    {
      printf("Error: Operation timed out after %ld seconds.\n",
             sftp->timeout);
      return TRUE;
    }
  
  switch (sftp->error)
    {      
     case SSH_FX_OK:
      return FALSE;
  
     case SSH_FX_EOF:
      printf("Error: tried to read at end of file.\n");
      return TRUE;

     case SSH_FX_NO_SUCH_FILE:
      printf("Error: no such file.\n");
      return TRUE;

     case SSH_FX_PERMISSION_DENIED:
      printf("Error: permission denied.\n");
      return TRUE;

     case SSH_FX_BAD_MESSAGE:
      printf("Error: bad message received.\n");
      return TRUE;

     case SSH_FX_FAILURE:
      printf("Error: operation failed.\n");
      return TRUE;
      
     case SSH_FX_CONNECTION_LOST:
      printf("Error: connection was lost.\n");
      sftp->connected = FALSE;
      return TRUE;  
      
     case SSH_FX_NO_CONNECTION:
      printf("Error: connection not established.\n");
      sftp->connected = FALSE;
      return TRUE;      
    }
  
  printf("Error: Unknown error occured.\n");
  return TRUE;
}


/*
 *  These are convenience functions that are used to synchronize operation.
 *  (i.e. block until timeout or operation completed)
 * 
 *  Return values:
 * 
 *    FALSE  Operation was successful, and data can be found in the context
 *    TRUE   A timeout or an error occured and error message has been 
 *           displayed
 */

/* Open a file */ 

Boolean sftp_file_open(Sftp sftp, SshFileClient client,
                       const char *name, unsigned int flags,
                       SshFileAttributes attributes)
{
  ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);  
  ssh_file_client_open(client, name, flags, attributes, 
                       sftp_file_handle_callback, sftp);
  ssh_event_loop_run(); 
  ssh_cancel_timeouts(sftp_timeout_callback, sftp);
  
  return sftp_error(sftp);
}

/* Read data */

Boolean sftp_file_read(Sftp sftp, SshFileHandle handle, 
                       off_t offset, size_t len)
{  
  ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);  
  ssh_file_client_read(handle, offset, len, 
                       sftp_file_data_callback, sftp);
  ssh_event_loop_run(); 
  ssh_cancel_timeouts(sftp_timeout_callback, sftp);
  
  return sftp_error(sftp);
}
                       
/* Write data */

Boolean sftp_file_write(Sftp sftp, SshFileHandle handle, 
                        off_t offset, const unsigned char *buf,
                        size_t len)
{
  sftp->called = FALSE;
  ssh_file_client_write(handle, offset, buf, len, 
                        sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);  
      ssh_event_loop_run();  
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
  return sftp_error(sftp);
}
                      
/* Close file */

Boolean sftp_file_close(Sftp sftp, SshFileHandle handle)
{ 
  sftp->called = FALSE;
  ssh_file_client_close(handle, sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);    
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* Stat a file */

Boolean sftp_file_stat(Sftp sftp, SshFileClient client, const char *name)
{
  sftp->called = FALSE;
  ssh_file_client_stat(client, name, sftp_file_attribute_callback, sftp);  
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);    
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* lstat a file */

Boolean sftp_file_lstat(Sftp sftp, SshFileClient client, const char *name)
{
  sftp->called = FALSE;
  ssh_file_client_lstat(client, name, sftp_file_attribute_callback, sftp);  
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);    
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* fstat a file */

Boolean sftp_file_fstat(Sftp sftp, SshFileHandle handle)
{
  sftp->called = FALSE;
  ssh_file_client_fstat(handle, sftp_file_attribute_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp); 
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* setstat a file */

Boolean sftp_file_setstat(Sftp sftp, SshFileClient client,
                          const char *name, 
                          SshFileAttributes attributes)
{  
  sftp->called = FALSE;
  ssh_file_client_setstat(client, name, attributes,
                          sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);    
      ssh_event_loop_run();  
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
  
  return sftp_error(sftp); 
}

/* fsetstat a file */

Boolean sftp_file_fsetstat(Sftp sftp, SshFileHandle handle,
                           SshFileAttributes attributes)
{
  sftp->called = FALSE;  
  ssh_file_client_fsetstat(handle, attributes,
                           sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);     
      ssh_event_loop_run();  
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* opendir */

Boolean sftp_file_opendir(Sftp sftp, SshFileClient client,
                          const char *name)
{
  sftp->called = FALSE;
  ssh_file_client_opendir(client, name, sftp_file_handle_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);
      ssh_event_loop_run();  
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
  
  return sftp_error(sftp); 
}

/* Readdir */

Boolean sftp_file_readdir(Sftp sftp, SshFileHandle handle)
{
  sftp->called = FALSE;
  ssh_file_client_readdir(handle, sftp_file_name_callback, sftp);
  
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  /* Omit error message if this just happened to be our last file. */  
  if (!sftp->fired && sftp->error == SSH_FX_EOF)
    return TRUE;
  else
    return sftp_error(sftp); 
}

/* Remove a file */

Boolean sftp_file_remove(Sftp sftp, SshFileClient client,
                         const char *name)
{
  sftp->called = FALSE;
  ssh_file_client_remove(client, name, sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);  
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* Make a directory */

Boolean sftp_file_mkdir(Sftp sftp, SshFileClient client,
                        const char *name, 
                        SshFileAttributes attributes)
{
  sftp->called = FALSE;
  ssh_file_client_mkdir(client, name, attributes,
                        sftp_file_status_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp); 
}

/* Remove a directory */

Boolean sftp_file_rmdir(Sftp sftp, SshFileClient client,
                        const char *name)
{
  sftp->called = FALSE;
  ssh_file_client_rmdir(client, name, sftp_file_status_callback, sftp);
  if (!sftp->called)
    {  
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);  
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
  
  return sftp_error(sftp); 
}

/* Resolve a real path  */

Boolean sftp_file_realpath(Sftp sftp, SshFileClient client,
                           const char *path)
{
  sftp->called = FALSE;
  ssh_file_client_realpath(client, path, sftp_file_name_callback, sftp);
  if (!sftp->called)
    {
      ssh_register_timeout(sftp->timeout, 0, sftp_timeout_callback, sftp);    
      ssh_event_loop_run();
      ssh_cancel_timeouts(sftp_timeout_callback, sftp);
    }
      
  return sftp_error(sftp);   
}


/* Open the connection with given arguments */

#define SFTP_MAX_ARGS 128

Boolean sftp_open_connection(Sftp sftp)
{
  Boolean user_spec;
  char *args[SFTP_MAX_ARGS];
  int i;
  SftpCipherName cipher;

  if (sftp->remote_host == NULL || strlen(sftp->remote_host) == 0)
    {
      printf("Remote host not specified.");
      return 0;
    }
  
  if (sftp->connected)
    {
      printf("Disconnecting..\n");
      sftp_disconnect(0, NULL, sftp);
    }
  
  user_spec = sftp->remote_user != NULL && 
    strlen(sftp->remote_user) > 0;

  /* now execute ssh2 with -s sftp parameters */
  
  switch (ssh_pipe_create_and_fork(&sftp->remote_client_stream,
                                   NULL))
    {
    case SSH_PIPE_ERROR:
      ssh_fatal("ssh_pipe_create_and_fork() failed");
      
    case SSH_PIPE_PARENT_OK:      

      sftp->child_pid = ssh_pipe_get_pid(sftp->remote_client_stream);

      /* Try to wrap this as the server */
      
      sftp->remote_client = 
        ssh_file_client_wrap(sftp->remote_client_stream);
      printf("remote path : ");   
      
      if (sftp_pwd(0, NULL, sftp))
        {
          printf("\nremote server failed.\n");
          sftp->connected = FALSE;
          return TRUE;
        }
      else
        {
          sftp->connected = TRUE;
          return FALSE;
        }
      
    case SSH_PIPE_CHILD_OK:
      /* execlp("sftp-server", "sftp-server", NULL); */
      
      i = 0;
      args[i++] = sftp->ssh_path;

      if (sftp->remote_port && *sftp->remote_port)
        {
           args[i++] = "-p";
           args[i++] = sftp->remote_port;
         }
       if (user_spec)
         {
           args[i++] = "-l";
           args[i++] = sftp->remote_user;
         }
       if (sftp->debug)
         {
           args[i++] = "-d";
           args[i++] = sftp->debug_level;
         }

       for (cipher = sftp->cipher_list; 
            cipher != NULL; 
            cipher = cipher->next)
         {
           SSH_ASSERT(i < SFTP_MAX_ARGS);
           
           args[i++] = "-c";
           args[i++] = cipher->name;
         }

       args[i++] = sftp->remote_host;
       args[i++] = "-s";
       args[i++] = "sftp";
       args[i] = NULL;

       SSH_ASSERT(i < SFTP_MAX_ARGS);

       for (i = 0; args[i]; i++)
         ssh_debug("args[%d] = %s", i, args[i]);

       execvp(sftp->ssh_path, args);
       
       exit(254);
    }  
  /* not reached */
  return TRUE;
}

/*
 * SFTP user commands (mostly taken from the old BSD FTP client)
 * 
 * The format of this table is:
 *  
 * {
 *   "command name", 
 *    min_parameters, max_parameters, 
 *    {"param1_name", "param2_name"},
 *    action, conn
 *    "help text"
 * }
 *  
 * if max_parameters < 0, then this command is currently unsupported, 
 * and act.unsupported_text is printed. Otherwise, the act.proc function
 * is called with appropriate arguments. conn is TRUE for all functions
 * that require that sftp is in connected state.
 *  
 * If there can be more than 2 arguments, set max_parameters to 3.
 * 
 */

struct SftpCmdRec 
{
  const char *cmd_name;
  int min_pars;
  int max_pars;
  char *parm_names[2];
  int (*action)(int argc, char **argv, Sftp ctx);
  Boolean conn;
  char *help_text;
};

struct SftpCmdRec sftp_cmd[];

/* get tty dimensions in characters */

void sftp_get_win_dim(int *width, int *height)
{
#ifdef TIOCGWINSZ
  struct winsize ws;
    
  if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0)
    {
      if (width != NULL)
        *width = ws.ws_col;
      if (height != NULL)
        *height = ws.ws_row;
    }    
  else  
#endif 
    {
      if (width != NULL)
        *width = 80;
      if (height != NULL)
        *height = 25;    
    }
}

/* expand a path name (basically strcat) */

char *sftp_path_expand(const char *path, const char *name, Boolean slash)
{
  size_t ln, lp;
  char *r;
  
  ln = strlen(name);
  lp = strlen(path);
  
  if (name[0] == '/')
    {
      if (slash && name[ln - 1] != '/')
        {
          r = ssh_xmalloc(ln + 2);
          snprintf(r, ln + 2, "%s/", name);
        }
      else
        r = ssh_xstrdup(name);
    }
  else
    {
      if (path == NULL || strlen(path) == 0)
        path = ".";  

      r = ssh_xmalloc(lp + ln + 3);
            
      if (slash && name[ln > 0 ? ln - 1 : 0] != '/')
        snprintf(r, lp + ln + 3, "%s/%s/", path, name);
      else
        snprintf(r, lp + ln + 3, "%s/%s", path, name);      
    }
      
  return r;
}

/* Simple compare function */

int sftp_page_compar(const void *a, const void *b)
{
  return strcmp(*((const char **) a), *((const char **) b));
}


/* Prompt for return */

void sftp_page_prompt_return(Sftp sftp)
{
  char *line;

  line = NULL;

  if (fflush(stdout))
    {
      perror("sftp_page_prompt_return");
      printf("\nErrno: %d\n", errno);
    }
  
  if (ssh_readline("<press return for more>", (unsigned char **)&line, fileno(stdin)) == -1)
    ssh_warning("sftp_page_prompt_return: error getting char.");

  printf("\r\n");
}

/* Sort and paginate a list of strings that ends with NULL. */

void sftp_page_list(char **list, Sftp sftp)
{
  int i, j, k, h, w, max_width, no_elem, columns, rows;
    
  /* Count the number of elements and max width */
  
  max_width = 0;  
  for (no_elem = 0; list[no_elem] != NULL; no_elem++)
    {
      w = strlen(list[no_elem]);
      if (w > max_width)
        max_width = w;      
    }
  
  if (no_elem == 0)
    return;
  
  /* Sort the list */
  
  if (sftp->sort)
    qsort(list, no_elem, sizeof(char *), sftp_page_compar);
    
  /* Compute columns and rows.. */
  
  max_width += 2;
  sftp_get_win_dim(&w, &rows);
  columns = w / max_width;
  if (columns < 1)
    columns = 1;

  /* Print the list */
  k = 0;
  
  while (k < no_elem)
    {  
      h = (no_elem - k) / columns + 1;
      
      if (sftp->page && h > (rows - 1)) 
        h = rows - 1;
      
      for (i = 0; i < h; i++)
        {
          for (j = 0; j < columns; j++)
            {
              if (j * h + i + k >= no_elem)
                continue;         
              printf("%*s", -max_width, list[j * h + i + k]);     
            }      
          printf("\r\n");
        }
      k += h * columns;
      
      if (k < no_elem)
        {
          /*      printf("\r\n");*/
          sftp_page_prompt_return(sftp);
        }
      
    }

  fflush(stdout);
  
}

/* Command not supported. */

int sftp_not_sup(int argc, char **argv, Sftp ctx)
{
  printf("Command %s not supported.\n", argv[0]); 
  return 0;
}

/* Command is a "no-op" */

int sftp_no_op(int argc, char **argv, Sftp ctx)
{
  printf("Command %s has currently no effect.\n", argv[0]); 
  return 0;
}

/* Print a short help text */

int sftp_help(int argc, char **argv, Sftp ctx)
{ 
  int i, j, k, n;
  char **l, *pa;
  
  /* Print all commands */
  
  if (argc < 2)
    {
      n = 0;
      for (i = 0; sftp_cmd[i].cmd_name != NULL; i++)
        if (sftp_cmd[i].help_text != NULL)
          n++;

      l = ssh_xcalloc(n + 1, sizeof(char *));
      
      for (i = 0, j = 0; sftp_cmd[i].cmd_name != NULL; i++)
        if (sftp_cmd[i].help_text != NULL)
          l[j++] = ssh_xstrdup(sftp_cmd[i].cmd_name);
      
      sftp_page_list(l, ctx);
      ssh_xfree(l);
      
      printf("\n? command  for more information on a specific "
             "command.\n");      
      return 0;
    }

  /* Help on a specific command */
  
  for (i = 0; argv[1][i] != '\0'; i++)
    argv[1][i] = tolower(argv[1][i]);
  
  for (i = 0; sftp_cmd[i].cmd_name != NULL; i++)
    {
      if (strcmp(sftp_cmd[i].cmd_name, argv[1]) == 0)
        {
          if (sftp_cmd[i].help_text == NULL)
            {
              printf("Help: No help available for %s.\n", argv[1]);
              return -1;
            }
          
          printf("\n    %s ", argv[1]);
          
          for (j = 0; j < 2; j++)
            {
              if (sftp_cmd[i].parm_names[j] == NULL)
                continue;             
              
              pa = ssh_xstrdup(sftp_cmd[i].parm_names[j]);
              for (k = 0; pa[k] != '\0'; k++)
                if (isspace(pa[k]))
                  pa[k] = '_';        
              if (j < sftp_cmd[i].min_pars)
                printf("%s ", pa);
              else
                printf("[%s] ", pa);          

              ssh_xfree(pa);
            }
          
          printf("\n\n        %s\n\n", sftp_cmd[i].help_text);
          return 0;
        }
    }    
  
  printf("Help: Unknown command %s.\n\n", argv[1]);  
  return -1;
}

/* Toggle bell */

int sftp_bell(int argc, char **argv, Sftp ctx)
{
  ctx->bell = !ctx->bell;
  if (ctx->bell)
    printf("Bell enabled.\n");
  else
    printf("Bell disabled.\n");

  return 0;
}
  
/* Disconnect */

int sftp_disconnect(int argc, char **argv, Sftp sftp)
{ 
  if (sftp->connected)
    ssh_file_client_destroy(sftp->remote_client);
  
  ssh_xfree(sftp->local_path);
  sftp->local_path = ssh_xstrdup(".");
  ssh_xfree(sftp->remote_path);  
  sftp->remote_path = ssh_xstrdup(".");
  
  sftp->connected = FALSE;
  return 0;
}

/* Quit */

int sftp_quit(int argc, char **argv, Sftp ctx)
{
  ctx->alive = FALSE;
  return sftp_disconnect(argc, argv, ctx);
}

/* Change the remote directory */

int sftp_cd(int argc, char **argv, Sftp sftp)
{ 
  char *p;
  
  /* simulate "cd" with realpath calls */
  
  p = sftp_path_expand(sftp->remote_path, argv[1], TRUE);
  if (sftp_file_stat(sftp, sftp->remote_client, p))
    {
      ssh_xfree(p);
      return -1;
    } 
  if ((sftp->attributes->permissions & S_IFMT) != S_IFDIR)
    {
      ssh_xfree(p);
      printf("Error: Not a directory.\n");
      return -1;
    }
  
  if (sftp_file_realpath(sftp, sftp->remote_client, p))
    {
      ssh_xfree(p);
      return -1;
    }
  
  ssh_xfree(sftp->remote_path);
  sftp->remote_path = ssh_xstrdup(sftp->name);
  ssh_xfree(p);
  
  return 0;
}  
 
/* Delete a remote file */ 

int sftp_delete(int argc, char **argv, Sftp sftp)
{ 
  int err;
  char *p;
  
  p = sftp_path_expand(sftp->remote_path, argv[1], FALSE);    
  err = sftp_file_remove(sftp, sftp->remote_client, p);
  ssh_xfree(p);

  return err;
}  

/* Delete a local file */

int sftp_ldelete(int argc, char **argv, Sftp sftp)
{ 
  int err;
  char *p;
  
  p = sftp_path_expand(sftp->local_path, argv[1], FALSE);    
  err = sftp_file_remove(sftp, sftp->local_client, p);
  ssh_xfree(p);

  return err;
}  

/* Display given remote or local directory */

int sftp_dir_both(char *path, SshFileClient client, Sftp sftp)
{
  size_t i, n, allocated;
  int row, rows, next_break, cols;
  char **names;
  SshFileHandle handle;

  if (sftp_file_opendir(sftp, client, path))
    return -1;
  handle = sftp->handle;

  allocated = 32;
  names = ssh_xmalloc(2 * allocated * sizeof (char *));
  n = 0;
  
  /* Read in the directory entries */
  
  while (!sftp_file_readdir(sftp, handle))
    {
      names[2*n] = ssh_xstrdup(sftp->name);
      names[2*(n++) + 1] = ssh_xstrdup(sftp->long_name);
              
      if (n >= allocated)
        {
          allocated *= 2;
          names = ssh_xrealloc(names, 2 * allocated * sizeof (char *));  
        }     
    }
  
  if (n > 0 && sftp->sort)
    qsort(names, n, 2 * sizeof (char *), sftp_page_compar); 
  
  sftp_get_win_dim(&cols, &rows);  
  
  row = 1;
  next_break = rows - 1;
  for (i = 0; i < n; i++)
    {
      printf("%s\n", names[2*i+1]);   
      row += strlen(names[2*i+1]) / cols + 1;
      
      if (sftp->page && i < (n - 1) && row >= next_break)
        {
          sftp_page_prompt_return(sftp);
          next_break += rows - 1;
        }
    }
  
  /* Free the file names */
  
  for(i = 0; i < n; i++)
    {
      ssh_xfree(names[2*i]);
      ssh_xfree(names[2*i+1]); 
    }
  ssh_xfree(names);
      
  sftp_file_close(sftp, handle);
  printf("\n");
  return 0;
}

/* Display remote directory */

int sftp_dir(int argc, char **argv, Sftp sftp)
{ 
  int i, err;
  char *p;
  
  if (argc < 2)
    return sftp_dir_both(sftp->remote_path, sftp->remote_client, sftp);

  err = 0;
  for (i = 1; i < argc; i++)
    {
      p = sftp_path_expand(sftp->remote_path, argv[i], TRUE);      
      err |= sftp_dir_both(p, sftp->remote_client, sftp);
      ssh_xfree(p);
    }
      
  return err;
}  

/* our progress indicator */

void sftp_kitt(off_t pos, off_t total, int width)
{
  int i, p;

  p = width * pos / total;  

  printf("\r\n|");
  for (i = 1; i < width - 2; i++)
    {
      switch(i - p)
        {
         case 0:
          putchar('O');
          break;
          
         case 1:
         case -1:
          putchar('o');
          break;
          
         default:
          putchar('.');
        }
    }  
  putchar('|');
  fflush(stdout);
}

/* Move a file from one "client" to another */

int sftp_move_file(SshFileClient src_cl, char *src_path,
                   SshFileClient dest_cl, char *dest_path,
                   Sftp sftp)
{
  off_t offset;
  size_t src_len, file_len;
  int width;
  SshFileHandle src_handle = NULL, dest_handle = NULL;
  
  if (sftp_file_open(sftp, src_cl, src_path, O_RDONLY, NULL))
    {
      goto close_error;
    }
  src_handle = sftp->handle;
  
  if (sftp_file_open(sftp, dest_cl, dest_path, O_CREAT | O_TRUNC | O_WRONLY, NULL))
    {
      goto close_error;
    }
  dest_handle = sftp->handle;  
  offset = 0;

  /* stat the file in order to get the real length */
  
  if (sftp->hash)
    {  
      if (sftp_file_fstat(sftp, src_handle))
        goto close_error;
      file_len = sftp->attributes->size;      

      printf("Transferring %s -> %s  (%luk)\n",
             src_path, dest_path, (unsigned long) (file_len >> 10) + 1);
      
      sftp_get_win_dim(&width, NULL);      
      sftp_kitt(0, file_len, width);
    }
  
  /* move the file */
    
  do
    {
      if (sftp_file_read(sftp, src_handle, offset, SFTP_BUF_SIZE))
        goto close_error;       
      src_len = sftp->len;
      
      if (src_len > 0)
        if (sftp_file_write(sftp, dest_handle, offset, sftp->data, src_len))
          goto close_error;
      offset += src_len;
      
      if (sftp->hash)
        sftp_kitt(offset, file_len, width);
    }
  while (src_len == SFTP_BUF_SIZE);
  
  if (sftp->hash)
    putchar('\n');  
  
  sftp_file_close(sftp, src_handle);
  sftp_file_close(sftp, dest_handle);
  return 0;
      
close_error:
  if (src_handle != NULL)
    sftp_file_close(sftp, src_handle);
  if (dest_handle != NULL)
    sftp_file_close(sftp, dest_handle);
  return -1;
}

/* Get a remote file */

int sftp_get(int argc, char **argv, Sftp sftp)
{   
  int err;
  char *src_p, *dest_p;
  
  src_p = sftp_path_expand(sftp->remote_path, argv[1], FALSE);
  dest_p = sftp_path_expand(sftp->local_path, 
                            argc == 3 ? argv[2] : argv[1], FALSE);
  err = sftp_move_file(sftp->remote_client, src_p, 
                       sftp->local_client, dest_p, sftp);
  ssh_xfree(src_p);
  ssh_xfree(dest_p);
  return err;
}  

/* Toggle globbing for mdelete, mget, and mput. */

int sftp_glob(int argc, char **argv, Sftp ctx)
{ 
  ctx->globbing = !ctx->globbing;
  
  if (ctx->globbing)
    printf("Globbing enabled.\n");
  else
    printf("Globbing disabled.\n");
 
  return -1;
}  

/* Toggle progress indicator on / off. */
  

int sftp_hash(int argc, char **argv, Sftp ctx)
{ 
  ctx->hash = !ctx->hash;
  
  if (ctx->hash)
    printf("Progress indicator enabled.\n");
  else
    printf("Progress indicator disabled.\n");
  
  return 0;
}  

/* Change local directory. */

int sftp_lcd(int argc, char **argv, Sftp sftp)
{ 
  char *p;
  
  /* simulate "cd" with realpath calls */
  
  p = sftp_path_expand(sftp->local_path, argv[1], TRUE);
  
  if (sftp_file_stat(sftp, sftp->local_client, p))
    {
      ssh_xfree(p);
      return -1;
    } 
  if ((sftp->attributes->permissions & S_IFMT) != S_IFDIR)
    {
      ssh_xfree(p);
      printf("Error: Not a directory.\n");
      return -1;
    }
  
  if (sftp_file_realpath(sftp, sftp->local_client, p))
    {
      ssh_xfree(p);
      return -1;
    }
  
  ssh_xfree(sftp->local_path);
  sftp->local_path = ssh_xstrdup(sftp->name);
  ssh_xfree(p);
  
  return 0;
}  

/* Display given remote or local directory in short format */

int sftp_ls_both(char *path, SshFileClient client, Sftp sftp)
{
  size_t a, i, n, allocated;
  char **names;
  SshFileHandle handle;
  long unsigned type;

  if (sftp_file_opendir(sftp, client, path))
    return -1;
  handle = sftp->handle;

  allocated = 32;
  names = ssh_xmalloc(allocated * sizeof (char *));
  n = 0;
  
  /* Read in the directory entries */
  
  while (!sftp_file_readdir(sftp, handle))
    {
      if (sftp->attributes->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        type = sftp->attributes->permissions & S_IFMT;
      else
        type = 0;
      
      if (type == S_IFDIR || type == S_IFLNK)
        {
          a = strlen(sftp->name);         
          names[n] = ssh_xmalloc(a + 2);
          snprintf(names[n], a + 2, "%s%c", sftp->name,
                   type == S_IFDIR ? '/' : '@'); 
        }
      else
        names[n] = ssh_xstrdup(sftp->name);      
      n++;    
          
      if (n >= allocated)
        {
          allocated *= 2;
          names = ssh_xrealloc(names, allocated * sizeof (char *));  
        }
      ssh_xfree(sftp->name);
      ssh_xfree(sftp->long_name);
      ssh_xfree(sftp->attributes);
      
    }
  names[n] = NULL;
  
  /* Paginate nad format the output */  
  sftp_page_list(names, sftp);
            
  /* Free the file names */
  
  for (i = 0; i < n; i++)
    ssh_xfree(names[i]);
  ssh_xfree(names);      
  sftp_file_close(sftp, handle);
  
  printf("\n");
  return 0;
}


/* Display local directory. */

int sftp_ldir(int argc, char **argv, Sftp sftp)
{ 
  int i, err;
  
  if (argc < 2)
    return sftp_dir_both(sftp->local_path, sftp->local_client, sftp);
  err = 0;
  for (i = 1; i < argc; i++)
    err |= sftp_dir_both(argv[i], sftp->local_client, sftp);
  
  return err; 
}  

/* List a local directory in short format . */

int sftp_lls(int argc, char **argv, Sftp sftp)
{ 
  int i, err;
  char *p;
  
  if (argc < 2)
    return sftp_ls_both(sftp->local_path, sftp->local_client, sftp);
  err = 0;
  
   for (i = 1; i < argc; i++)
    {
      p = sftp_path_expand(sftp->local_path, argv[i], TRUE);      
      err |= sftp_ls_both(p, sftp->local_client, sftp);
      ssh_xfree(p);
    }
   
  return err; 
}  

/* List a remote directory in short format . */

int sftp_ls(int argc, char **argv, Sftp sftp)
{
  int i, err;
  char *p;
  
  if (argc < 2)
    return sftp_ls_both(sftp->remote_path, sftp->remote_client, sftp);
  err = 0;
  
  for (i = 1; i < argc; i++)
    {
      p = sftp_path_expand(sftp->remote_path, argv[i], TRUE);      
      err |= sftp_ls_both(p, sftp->remote_client, sftp);
      ssh_xfree(p);
    }
      
  return err;
}  

/* Get multiple remote files. */

int sftp_mget(int argc, char **argv, Sftp ctx)
{ 
  /* XXX */
  return -1;
}  

/* Make a remote directory. */

int sftp_mkdir(int argc, char **argv, Sftp sftp)
{ 
  int err;
  char *p;
  SshFileAttributes attrs;
  
  p = sftp_path_expand(sftp->remote_path, argv[1], FALSE);
  attrs = ssh_xmalloc(sizeof (*attrs));
  attrs->flags = 0;
  
  err = sftp_file_mkdir(sftp, sftp->remote_client, p, attrs);  
  ssh_xfree(p);
  ssh_xfree(attrs);
                  
  return err;
}  

/* Transfer multiple files to remote end. */

int sftp_mput(int argc, char **argv, Sftp ctx)
{   
  /* XXX */
  return -1;
}  

/* Open an connection to remote sftp (ssh2) server. */

int sftp_open(int argc, char **argv, Sftp sftp)
{ 
  ssh_xfree(sftp->remote_host);
  sftp->remote_host = ssh_xstrdup(argv[1]);
  
  if ( argc >= 3 )
    {
      ssh_xfree(sftp->remote_port);
      sftp->remote_port = ssh_xstrdup(argv[2]);
    }

  if (sftp_open_connection(sftp))
    return -1;
  
  return 0;  
}  

/* Toggle paging. */

int sftp_page(int argc, char **argv, Sftp ctx)
{ 
  ctx->page = !ctx->page;
  
  if (ctx->page)
    printf("Paging enabled.\n");
  else
    printf("Paging disabled.\n");
  
  return -1;
}  

/* Toggle interactive prompting. */

int sftp_prompt(int argc, char **argv, Sftp ctx)
{ 
  ctx->prompt = !ctx->prompt;
  
  if (ctx->hash)
    printf("Interactive prompting enabled.\n");
  else
    printf("Interactive prompting disabled.\n");
  
  return -1;
}  

/* Transfer a local file on the remote machine. */
 
int sftp_put(int argc, char **argv, Sftp sftp)
{ 
  int err;
  char *src_p, *dest_p;
  
  src_p = sftp_path_expand(sftp->local_path, argv[1], FALSE);
  dest_p = sftp_path_expand(sftp->remote_path, 
                            argc == 3 ? argv[2] : argv[1], FALSE);
  err = sftp_move_file(sftp->local_client, src_p, 
                       sftp->remote_client, dest_p, sftp);
  ssh_xfree(src_p);
  ssh_xfree(dest_p);
  return err;
}  

/* Print the current working directory on the remote machine. */

int sftp_pwd(int argc, char **argv, Sftp sftp)
{ 
  if (sftp_file_realpath(sftp, sftp->remote_client, sftp->remote_path))
    return -1;
  
  ssh_xfree(sftp->remote_path);
  sftp->remote_path = ssh_xstrdup(sftp->name);
  printf("%s\n", sftp->remote_path);
  
  return 0;
}  

/* Print the current working directory on the local machine. */

int sftp_lpwd(int argc, char **argv, Sftp sftp)
{ 
  if (sftp_file_realpath(sftp, sftp->local_client, sftp->local_path))
    return -1;
  
  ssh_xfree(sftp->local_path);
  sftp->local_path = ssh_xstrdup(sftp->name);
  printf("%s\n", sftp->local_path);
  
  return 0;
}  


/* Show the current status of sftp. */

int sftp_status(int argc, char **argv, Sftp sftp)
{ 
  if (sftp->connected)
    printf("Connected to %s.\n", sftp->remote_host);
  else
    printf("Not connected.\n");

  /*  
  printf("\nTransferred  out: %g kbytes\n", sftp->trans_in / 1024.0);
  printf("              in: %g kbytes\n", sftp->trans_out / 1024.0);
  printf("           total: %g kbytes\n\n", 
         (sftp->trans_in + sftp->trans_out) / 1024.0);
   */
  
  printf("Prompting:        %s\n", sftp->prompt ? "yes" : "no");
  printf("Verbose mode:     %s\n", sftp->verbose ? "yes" : "no");
  printf("Globbing:         %s\n", sftp->globbing ? "yes" : "no");
  printf("Bell:             %s\n", sftp->bell ? "yes" : "no");
  printf("Quiet mode:       %s\n", sftp->quiet ? "yes" : "no");
  printf("Hashes:           %s\n", sftp->hash ? "yes" : "no");
  printf("Sorting:          %s\n", sftp->sort ? "yes" : "no");
  printf("Paginate:         %s\n", sftp->page ? "yes" : "no");
  printf("Timeout:          %ld sec\n", sftp->timeout);
  
  return 0;
}  

/* Toggle sorting. */

int sftp_sort(int argc, char **argv, Sftp ctx)
{ 
  ctx->sort = !ctx->sort;
  
  if (ctx->sort)
    printf("Sorting enabled.\n");
  else
    printf("Sorting disabled.\n");
  
  return -1;
}  

/* Set timeout */

int sftp_timeout(int argc, char **argv, Sftp ctx)
{ 
  int t;
  
  t = atoi(argv[1]);
  if (t < 1)
    {
      printf("%s: illegal timeout value %s.\n", argv[0], argv[1]);
      return -1;      
    }
  ctx->timeout = t;
  
  return 0;
}  

/* Identify yourself to the remote FTP server */

int sftp_user(int argc, char **argv, Sftp sftp)
{ 
  ssh_xfree(sftp->remote_user);
  sftp->remote_user = ssh_xstrdup(argv[1]);  
    
  if (sftp_open_connection(sftp))
    return -1;
  
  return 0;
}  

/* Toggle verbose mode on/off. */

int sftp_verbose(int argc, char **argv, Sftp ctx)
{ 
  ctx->verbose = !ctx->verbose;
  
  if (ctx->verbose)
    printf("Verbose mode enabled.\n");
  else
    printf("Verbose mode disabled.\n");
  
  return -1;
}  

/*
 *  A jump table for sftp commands  
 */

struct SftpCmdRec sftp_cmd[] =
{
    {
      "?", 0, 1, {"keyword", NULL}, sftp_help, FALSE,
      "Print a short help text",
    },
  
    {
      "ascii", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL,
    },
  
    {
      "bell", 0, 0, {NULL, NULL}, sftp_bell, FALSE,
      "Sound a bell after each file transferred."
    },
  
    {
      "binary", 0, 0, {NULL, NULL}, sftp_no_op, FALSE,
      NULL,
    },
  
    {
      "bye", 0, 0, {NULL, NULL}, sftp_quit, FALSE,
      "Disconnect and quit."
    },
  
    {
      "cd", 1, 1, {"remote directory", NULL}, sftp_cd, TRUE,
      "Change the remote directory."
    },
  
    {
      "delete", 1, 1, {"remote file", NULL}, sftp_delete, TRUE,
      "Delete a remote file."
    },
  
    {
      "rm", 1, 1, {"remote file", NULL}, sftp_delete, TRUE,
      "Delete a remote file."
    },
    
   {
      "ldelete", 1, 1, {"local file", NULL}, sftp_ldelete, FALSE,
      "Delete a local file."
    },
  
    {
      "lrm", 1, 1, {"local file", NULL}, sftp_ldelete, FALSE,
      "Delete a local file."
    },
    
    {
      "close", 0, 0, {NULL, NULL}, sftp_disconnect, TRUE,
      "Close connection."
    },
  
    {
      "dir", 0, 2, {"remote directory", "local file"}, sftp_dir, TRUE,
      "Display remote directory."
    },
  
    {
      "disconnect", 0, 0, {NULL, NULL}, sftp_disconnect, TRUE,
      "Close connection."
    },
  
    {
      "get", 1, 2, {"remote file", "local file"}, sftp_get, TRUE,
      "Get a remote file."
    },

    {
      "hash", 0, 0, {NULL, NULL}, sftp_hash, FALSE,
      "Toggle progress indicator."
    },

    {
      "help", 0, 1, {"keyword", NULL}, sftp_help, FALSE,
      "Print a short help text."
    },
  
    {
      "idle", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL    
    },
  
    {
      "lcd", 1, 1, {"local directory", NULL}, sftp_lcd, FALSE,
      "Change local directory."
    },

    {
      "ldir", 0, 1, {"local directory", NULL}, sftp_ldir, FALSE,
      "Display local directory."    
    },
  
    {
      "lls", 0, 2, {"local directory", "local file"}, sftp_lls, FALSE,
      "List local directory in short format." 
    },
  
    {
      "lpwd", 0, 0, {NULL, NULL}, sftp_lpwd, FALSE,
      "Print the current working directory on the local machine."
    },
  
    {
      "ls", 0, 2, {"remote directory", "local file"}, sftp_ls, TRUE,
      "List remote directory in short format."
    },
  
    {
      "macdef", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL      
    },
  /*
    {  
      "mget", 1, 3, {"remote files", NULL}, sftp_mget, TRUE,
      "Get multiple remote files."
    },
   */
    {
      "mkdir", 1, 1, {"remote directory", NULL}, sftp_mkdir, TRUE,
      "Make a remote directory."      
    },
  /*  
    {
      "mput", 1, 3, {"local files", NULL}, sftp_mput, TRUE,
      "Transfer multiple files to remote end."
    },
   */
    {
      "nmap", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL,
    },
  
    {
      "open", 1, 2, {"host", "port"}, sftp_open, FALSE,
      "Open an connection to remote sftp (ssh2) server."
    }, 

    {
      "page", 0, 0, {NULL, NULL}, sftp_page, FALSE,
      "Toggle paging."
    },
  
    {
      "passive", 0, 0, {NULL, NULL}, sftp_no_op, FALSE,
      NULL,      
    },
  
    {
      "prompt", 0, 0, {NULL, NULL}, sftp_prompt, FALSE,
      "Toggle interactive prompting."      
    },
  
    {
      "proxy", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL,
    },

    {
      "put", 1, 2, {"local file", "remote file"}, sftp_put, TRUE,
      "Transfer a local file on the remote machine.",      
    },
  
    {
      "pwd", 0, 0, {NULL, NULL}, sftp_pwd, TRUE,
      "Print the current working directory on the remote machine."
    },

    {
      "quit", 0, 0, {NULL, NULL}, sftp_quit, FALSE,
      "Disconnect and quit."      
    },
  
    {
      "recv", 1, 2, {"remote file", "local file"}, sftp_get, TRUE,
      "Get a remote file."      
    },
  
    {
      "reget", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL,      
    },
  
    {
      "type", 0, 1, {"type name", NULL}, sftp_no_op, FALSE,
      NULL,      
    },
  
    {
      "status", 0, 0, {NULL, NULL}, sftp_status, FALSE,
      "Show the current status of sftp."
    },
  
    {
      "sort", 0, 0, {NULL, NULL}, sftp_sort, FALSE,
      "Toggle sorting."
    },
  
    {
      "timeout", 1, 1, {"seconds", NULL}, sftp_timeout, FALSE,
      "Set timeout."    
    },
  
    {
      "umask", 0, 0, {NULL, NULL}, sftp_not_sup, FALSE,
      NULL,      
    },
  
    {
      "user", 1, 2, {"username", "password"}, sftp_user, FALSE,
      "Identify yourself to the remote FTP server."      
    }, 
    
    {
      "verbose", 0, 0, {NULL, NULL}, sftp_verbose, FALSE,
      "Toggle verbose mode on/off."      
    },
  
    {
      NULL,  0, 0, {NULL, NULL}, NULL, FALSE, NULL
    }
};

/* Allocate a new sftp structure */
    
Sftp sftp_init(void);

Sftp sftp_init()
{
  Sftp sftp;

  sftp = ssh_xcalloc(1, sizeof(*sftp));
  sftp->connected = FALSE;
  sftp->remote_host = NULL;
  sftp->remote_user = NULL;
  sftp->remote_port = NULL;
  sftp->prompt = FALSE;
  sftp->verbose = FALSE;
  sftp->globbing = TRUE;
  sftp->bell = FALSE;
  sftp->quiet = FALSE;
  sftp->hash = TRUE;
  sftp->alive = TRUE;
  sftp->sort = TRUE;
  sftp->page = TRUE;
  sftp->debug = FALSE;
  sftp->debug_level = ssh_xstrdup("0");
  sftp->timeout = 30;
  sftp->local_path = ssh_xstrdup(".");
  sftp->remote_path = ssh_xstrdup(".");
  sftp->mask = NULL;

  sftp->child_pid = 0;
  
  /* Create the local server/client pair */  
  ssh_stream_pair_create(&sftp->local_server_stream, 
                         &sftp->local_client_stream);  
  sftp->local_server = 
    ssh_file_server_wrap(sftp->local_server_stream);
  sftp->local_client = 
    ssh_file_client_wrap(sftp->local_client_stream);
  
  sftp->connected = FALSE;
  sftp->remote_port = ssh_xstrdup("");
  sftp->remote_host = ssh_xstrdup("");

  sftp->ssh_path = ssh_xstrdup("ssh2");
  sftp->cipher_list = NULL;
  sftp->cipher_list_last = NULL;

  printf("local path  : ");
  if (sftp_lpwd(0, NULL, sftp))
    ssh_fatal("local client / server creation failed.");
 
  return sftp;
}



/* Free a sftp structure */

void sftp_free(Sftp sftp)
{
  if (sftp == NULL)
    return;
  
  ssh_stream_destroy(sftp->local_server_stream);
  ssh_stream_destroy(sftp->local_client_stream);
  ssh_xfree(sftp->remote_host);
  ssh_xfree(sftp->remote_port);
  ssh_xfree(sftp->remote_user);
  ssh_xfree(sftp->local_path);
  ssh_xfree(sftp->remote_path);
  ssh_xfree(sftp->mask);
  ssh_xfree(sftp);  
}


/* ssh_debug() callback */

void sftp_debug(const char *msg, void *context)
{
  Sftp sftp;  
  sftp = (Sftp) context;
  if (sftp->debug)
    fprintf(stderr, "debug: %s\r\n", msg);
}

SftpCipherName sftp_new_cipher_item(char *name)
{
  SftpCipherName r;

  r = (SftpCipherName)ssh_xcalloc(1, sizeof (struct SftpCipherNameRec));
  r->name = ssh_xstrdup(name);
  r->next = NULL;
  return r;
}

void fatal_signal_handler(int signal, void *context)
{
  Sftp session = (Sftp) context;
  
  if (session->child_pid == 0)
    ssh_fatal("\r\nReceived signal %d. No child to kill.", signal);

  /* Kill child-ssh. */
  if (kill(session->child_pid, signal) != 0)
    {
      SSH_TRACE(2, ("killing child process did not succeed."));
    }
  
  ssh_fatal("\r\nReceived signal %d. Child with pid %d killed.",
            signal,
            session->child_pid);
}

/* clear O_NONBLOCK flag from filedescriptor */
void clear_nonblock(int fd)
{
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  fcntl(fd, F_SETFL, 
        fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  fcntl(fd, F_SETFL,
        fcntl(fd, F_GETFL, 0) & ~O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
}
      
/*
 * 
 *  sftp main
 * 
 */

int main(int argc, char **argv)
{
  Sftp sftp;
  char *cmdbuf, *earg[2];
  char **parm, prompt_buf[40];
  int i, parms;
  
  /* Save program name. */
  
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];
  
  /* initializations */
  signal(SIGPIPE, SIG_IGN);
  ssh_event_loop_initialize();

  sftp = sftp_init();
  ssh_debug_register_callbacks(NULL, NULL, sftp_debug, (void *)sftp);

  /* parse command line parameters */

  while (argv[1] != NULL && *(argv[1]) == '-')
    {
      if (strcmp(argv[1], "-d") == 0)
        {
          if (argc < 3)
            {
              fprintf(stderr, "%s: option -d needs an argument.\n", av0);
              sftp_free(sftp);
              return -1;
            }
          sftp->debug = 1;
          ssh_xfree(sftp->debug_level);
          sftp->debug_level = ssh_xstrdup(argv[2]);
          ssh_debug_set_level_string(sftp->debug_level);
          argc -= 2;
          argv += 2;
        }
      else if (strcmp(argv[1], "-c") == 0)
        {
          if (argc < 3)
            {
              fprintf(stderr, "%s: option -c needs an argument.\n", av0);
              sftp_free(sftp);
              return -1;
            }
          if (sftp->cipher_list == NULL)
            {
              sftp->cipher_list_last = sftp_new_cipher_item(argv[2]);
              sftp->cipher_list_last->next = NULL;
              sftp->cipher_list = sftp->cipher_list_last;
            }
          else
            {
              sftp->cipher_list_last->next = sftp_new_cipher_item(argv[2]);
              sftp->cipher_list_last = sftp->cipher_list_last->next;
              sftp->cipher_list_last->next = NULL;
            }
          argc -= 2;
          argv += 2;
        }
      else if (strcmp(argv[1], "-v") == 0)
        {
          sftp->debug = 1;
          ssh_xfree(sftp->debug_level);
          sftp->debug_level = ssh_xstrdup("2");
          ssh_debug_set_level_string(sftp->debug_level);
          argc -= 1;
          argv += 1;
        }
      else if (strcmp(argv[1], "-S") == 0)
        {
          if (argc < 3)
            {
              fprintf(stderr, "%s: option -S needs an argument.\n", av0);
              sftp_free(sftp);
              return -1;
            }
          ssh_xfree(sftp->ssh_path);
          sftp->ssh_path = ssh_xstrdup(argv[2]);
          argc -= 2;
          argv += 2;
        }
      else if (strcmp(argv[1], "-p") == 0)
        {
          if (argc < 3)
            {
              fprintf(stderr, "%s: option -p needs an argument.\n", av0);
              sftp_free(sftp);
              return -1;
            }
          ssh_xfree(sftp->remote_port);
          sftp->remote_port = ssh_xstrdup(argv[2]);
          argc -= 2;
          argv += 2;
        }
      else
        {
          fprintf(stderr, "%s: Unknown option %s.\n", av0, argv[1]);
          sftp_free(sftp);
          return -1;
        }
    }
  
  if (argc > 4)
    {
      fprintf(stderr, "%s: Too many parameters.\n", av0);
      sftp_free(sftp);
      return -1;
    }

  if (argc >= 3)
    {      
      ssh_xfree(sftp->remote_user);
      sftp->remote_user = ssh_xstrdup(argv[2]);
    }
  
  if (argc >= 2)
    {
      ssh_xfree(sftp->remote_host);
      sftp->remote_host = ssh_xstrdup(argv[1]);
      if (strchr(sftp->remote_host, '#'))
        {
          ssh_xfree(sftp->remote_port);
          sftp->remote_port = ssh_xstrdup(strchr(sftp->remote_host, '#') + 1);
          *strchr(sftp->remote_host, '#') = '\0';
        }
    }

  ssh_register_signal(SIGHUP, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGINT, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGILL, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGABRT, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGFPE, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGBUS, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGSEGV, fatal_signal_handler, (void *)sftp);
  ssh_register_signal(SIGTERM, fatal_signal_handler, (void *)sftp);

  ssh_debug("host %s port %s", sftp->remote_host, sftp->remote_port);

  parm = ssh_xcalloc(SFTP_MAX_ARGS, sizeof(char *));
  
  
  /* try to form a connection, if it was requested in the 
     command line */
  
  if (sftp->remote_host != NULL && strlen(sftp->remote_host) > 0)
    sftp_open_connection(sftp);
  
  fflush(stdout);
  cmdbuf = NULL;
  earg[0] = NULL;
  earg[1] = NULL;

  /* XXX currently we don't need or want stdio or stdout in
     nonblocking mode. */

  /* Clear O_NONBLOCK from stdout */
  {      
      clear_nonblock(fileno(stdin));
      clear_nonblock(fileno(stdout));   
  }

  /* main loop */
  
  while (sftp->alive)
    {
      ssh_xfree(cmdbuf);
      cmdbuf = NULL;
      ssh_xfree(earg[0]);
      earg[0] = NULL;
      ssh_xfree(earg[1]);
      earg[1] = NULL;
            

      if (ssh_readline((const unsigned char *) "sftp>",
                       (unsigned char **) &cmdbuf, 0) < 0)
        {
          printf("\n"); /* XXX */
          sftp_quit(0, NULL, sftp);
        }
      else 
        {                
          printf("\n"); /* XXX */
          /* Cut the command line into arguments */
          
          i = 0;
          for (parms = 0; parms < SFTP_MAX_ARGS; parms++)
            {     
              while (isspace(cmdbuf[i]) && cmdbuf[i] != '\0')
                i++;
              if (cmdbuf[i] == '\0')
                break;

              parm[parms] = &cmdbuf[i];
              
              while (!isspace(cmdbuf[i]) && cmdbuf[i] != '\0')
                i++;
              
              if (cmdbuf[i] == '\0')
                {
                  parms++;
                  break;
                }
              cmdbuf[i++] = '\0';             
            }                 
          cmdbuf[i] = '\0';
          
          if (parms < 1)
            continue;

          /* Convert the command name to lower case */
          
          for (i = 0; (parm[0])[i] != '\0'; i++)
            (parm[0])[i] = tolower((parm[0])[i]);
          
          /* Search for the command in the jump table */

          for (i = 0; sftp_cmd[i].cmd_name != NULL; i++)
            if (strcmp(sftp_cmd[i].cmd_name, parm[0]) == 0)
              break;
             
          if (sftp_cmd[i].cmd_name == NULL)
            {
              ssh_warning("Unknown command %s.", parm[0]);
              continue;
            }
                  
          if (parms - 1 > sftp_cmd[i].max_pars)
            {
              ssh_warning("Too many parameters");
              continue;
            }

          if (sftp_cmd[i].conn && !sftp->connected)
            {
              ssh_warning("Not connected.");
              continue;       
            }
          
          /* fill in the missing parameters */
          
          while (parms <= sftp_cmd[i].min_pars)
            {
              snprintf(prompt_buf, sizeof(prompt_buf), "%s %s>", 
                       sftp_cmd[i].cmd_name,
                       sftp_cmd[i].parm_names[parms-1]);

              if (ssh_readline((const unsigned char *)prompt_buf,
                               (unsigned char **) &earg[parms-1], 0) <= 0)
                {
                  /* XXX */
                  ssh_warning(".. aborted");
                  goto cmd_ok;
                }
              printf("\n"); /* XXX */
              
              parm[parms] = earg[parms-1];
              parms++;
            }
          
          /* Ok, now call the appr. function */
          
          (*sftp_cmd[i].action)(parms, parm, sftp);
          
        cmd_ok:
          ;
        }
    }

  printf("\r\n"); /* XXX */

  ssh_event_loop_uninitialize();
  
  ssh_xfree(cmdbuf);
  ssh_xfree(earg[0]);
  ssh_xfree(earg[1]);
  ssh_xfree(parm);
  sftp_free(sftp);
  
  return 0;
}
