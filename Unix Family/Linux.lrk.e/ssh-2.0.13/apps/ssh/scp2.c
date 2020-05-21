/*

  scp2.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  A scp2 client 
 
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
#include "sshgetopt.h"
#include "sshtimemeasure.h"
#include "sshmatch.h"

#define SSH_DEBUG_MODULE "Scp2"

#undef OLD_FILE_COPY_LOOP

#define SCP_FILESERVER_TIMEOUT          300      /*XXX*/
#define SCP_BUF_SIZE                    0x8000
#define SCP_READ_MAX                    0x8000
#define SCP_WRITE_MAX                   0x8000
#define SCP_BUF_SIZE_MAX                0x40000
#define SCP_ERROR_MULTIPLE              -1
#define SCP_ERROR_USAGE                 1
#define SCP_ERROR_NOT_REGULAR_FILE      2
#define SCP_ERROR_CANNOT_STAT           3
#define SCP_ERROR_CANNOT_CREATE         4
#define SCP_ERROR_CANNOT_OPEN           5
#define SCP_ERROR_READ_ERROR            6
#define SCP_ERROR_WRITE_ERROR           7

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

/* This struct is used to create a list of files to be transfered. */
typedef struct ScpFileLocationRec {
  char *user;
  char *host;
  char *file;
  int  port;
  struct ScpFileLocationRec *next;
  /* Needed with '-r' flag and globbing */
  Boolean contains_wildcards;
  int is_dir; /* -1 = uninitialized, 1 = directory, 0 = not a directory */
  char *dir_mask;
  SshFileAttributes dir_attrs;
} *ScpFileLocation;

/* This struct is used to create a list of ciphers. */
typedef struct ScpCipherNameRec {
  char *name;
  struct ScpCipherNameRec *next;
} *ScpCipherName;

/* This is the struct, that holds practically all generally needed
   information in one place. We don't like globals...*/
typedef struct ScpSessionRec {
  Boolean verbose;
  /* If TRUE, only fatal errors will be displayed. */
  Boolean quiet;
  Boolean nostat; /* No statistics */
  /* If we stdout is a tty. */
  Boolean have_tty;
  char *debug_flag;
  /* Whether scp2 tries to preserve file-attributes */
  Boolean preserve_flag;
  /* Whether directories will be copied recursively */
  Boolean recurse_flag;
  /* If TRUE, source files will be unlinked (removed) after
     copying. */
  Boolean unlink_flag;
  /* pid of the child process, which exec's ssh2 */
  pid_t child_pid; 
  /* Default remote port */
  int port;
  /* If TRUE, scp2 doesn't actually copy any files, but just shows,
     what would've happened.*/
  Boolean do_not_copy;
  /* TRUE, if destination needs to be a directory. */
  Boolean need_dst_dir;
  Boolean dst_is_dir;
  Boolean dst_is_file;
  Boolean dst_is_local;
  char *ssh_path;
  char *ssh1_path;
  Boolean use_ssh1;
  ScpCipherName cipher_list;
  ScpCipherName cipher_list_last;
  SshFileClient dst_client;
  SshFileClient dst_local_client;
  SshFileServer dst_local_server;
  SshFileClient dst_remote_client;
  SshFileClient src_local_client;
  SshFileServer src_local_server;
  SshFileClient src_remote_client;
  char *src_remote_host;
  int src_remote_port;
  char *src_remote_user;
  ScpFileLocation src_list;
  ScpFileLocation src_list_tail;
  ScpFileLocation dst_location;
  char *current_dst_file;
  Boolean current_src_is_local;
  ScpFileLocation current_src_location;
  Boolean timeout_is_fatal;
  Boolean timeout_triggered;
  SshFileHandle tmp_handle;
  /* Contains SshFileClientError, returned by last operation. Note:
     this is overwritten by almost every file-operation.*/
  SshFileClientError tmp_status;
  /* Contain remote filename, short form. (Just the file name, no path
     etc.) */
  char *remote_file_name;
  /* Contains remote filename, long form. Actual form is remote server
     dependent. (our implementation gives an 'ls -l'-style output). */
  char *remote_file_long_name;
  /* File attributes, obtained with last call. */
  SshFileAttributes tmp_attributes;
  /* TRUE, if file attributes are current. */
  Boolean tmp_attributes_ok;
  char *tmp_data;
  int tmp_data_len;
  Boolean callback_fired;
  /* This will contain the error that scp2 will return with. */
  int error;
} *ScpSession;

typedef enum {
  SCP_FC_ERROR,
  SCP_FC_TIMEOUT,
  SCP_FC_RUNNING,
  SCP_FC_BUFFER_FULL,
  SCP_FC_READ_COMPLETE,
  SCP_FC_COMPLETE
} ScpFileCopyState;

typedef struct ScpFileCopyContextRec {
  ScpSession session;
  SshBuffer buffer;
  ScpFileCopyState state;
  SshFileHandle src_handle;
  SshFileHandle dst_handle;
  off_t file_size;
  off_t read_offset;
  off_t write_offset;
  size_t write_pending;
  int term_width;
} *ScpFileCopyContext;

/********************************************************************
 * Function prototypes for internal functions.
 ********************************************************************/
void usage(void);
void scp_set_error(ScpSession session, int error);
void scp_init_session(ScpSession session);
Boolean scp_check_wildcards(char *str);

ScpFileLocation scp_parse_location_string(char *str);
SshFileClient scp_open_remote_connection(ScpSession session,
                                         char *host,
                                         char *user, 
                                         int port);
void scp_set_src_remote_location(ScpSession session, 
                                 char *host, 
                                 int port, 
                                 char *user);
char *scp_file_basename(char *pathname);
Boolean scp_set_src_is_remote_location_ok(ScpSession session, 
                                          char *host, 
                                          int port, 
                                          char *user);
void scp_abort_if_remote_dead(ScpSession session, SshFileClient client);
void scp_is_dst_directory_callback(SshFileClientError error,
                                   SshFileAttributes attributes,
                                   void *context);
void scp_get_win_dim(int *width, int *height);
void scp_kitt(off_t pos, off_t total, int width);
Boolean scp_expand_wildcards(ScpFileLocation *loc_list_start,
                             ScpFileLocation *loc_list_tail,
                             char *basepath,
                             char *orig_glob_pattern,
                             ScpSession session);
Boolean scp_recurse_directories(ScpFileLocation *loc_list_start,
                                ScpFileLocation *loc_list_tail,
                                ScpSession session,
                                SshFileClient src_client);
void scp_file_handle_callback(SshFileClientError error, 
                              SshFileHandle handle, 
                              void *context);
SshFileHandle scp_file_open(ScpSession session,
                            SshFileClient client,
                            char *file,
                            int flags,
                            SshFileAttributes attributes);
void scp_file_status_callback(SshFileClientError error, void *context);
void scp_file_name_callback(SshFileClientError error, 
                            const char *name, 
                            const char *long_name,
                            SshFileAttributes attributes,
                            void *context);
void scp_file_attribute_callback(SshFileClientError error, 
                                 SshFileAttributes attributes,
                                 void *context);
void scp_file_read_callback(SshFileClientError error,
                            const unsigned char *data,
                            size_t len,
                            void *context);
int scp_file_fsetstat(ScpSession session,
                      SshFileHandle handle,
                      SshFileAttributes attributes);
int scp_file_remove(ScpSession session,
                    SshFileClient client,
                    const char *name);
Boolean scp_file_opendir(ScpSession session, SshFileClient client,
                         const char *name);
Boolean scp_file_readdir(ScpSession session, SshFileHandle handle);
Boolean scp_file_mkdir(ScpSession session, SshFileClient client,
                       const char *name, 
                       SshFileAttributes attributes);
int scp_file_close(ScpSession session, SshFileHandle handle);
SshFileAttributes scp_file_fstat(ScpSession session, 
                                 SshFileHandle handle);
SshFileAttributes scp_file_stat(ScpSession session,
                                const char *name,
                                SshFileClient client);
SshFileAttributes scp_file_lstat(ScpSession session,
                                const char *name,
                                 SshFileClient client);
int scp_file_read(ScpSession session, 
                  SshFileHandle handle,
                  off_t offset, 
                  char *buf,
                  size_t bufsize);
int scp_file_write(ScpSession session,
                   SshFileHandle handle, 
                   off_t offset, 
                   char *buf, 
                   size_t bufsize);
Boolean scp_move_file(ScpSession session,
                      char *src_host,
                      char *src_path,
                      SshFileClient src_client, 
                      char *dst_host,
                      char *dst_path,
                      SshFileClient dst_client);
void scp_set_next_src_location(void *context);
void scp_timeout_callback(void *context);
void scp_remote_dead_timeout(void *context);
void scp_remote_alive_callback(SshFileClientError error,
                               const char *name,
                               const char *long_name,
                               SshFileAttributes attrs,
                               void *context);
int scp_execute(ScpSession session);
ScpCipherName scp_new_cipher_item(char *name);

/* Debug stuff */
void scp_debug(const char *msg, void *context);
void scp_warning(const char *msg, void *context);
void scp_print_session_info(ScpSession session);
void scp_print_location_info(ScpFileLocation location);

#if 1
static char *str_concat_3(const char *s1, const char *s2, const char *s3)
{
  int l1 = strlen(s1), l2 = strlen(s2), l3 = strlen(s3);
  char *r = ssh_xmalloc(l1 + l2 + l3 + 1);

  strcpy(r, s1);
  strcpy(&(r[l1]), s2);
  strcpy(&(r[l1 + l2]), s3);

  return r;
}

static char *str_concat(const char *s1, const char *s2)
{
  int l1 = strlen(s1), l2 = strlen(s2);
  char *r = ssh_xmalloc(l1 + l2 + 1);
  strcpy(r, s1);
  strcpy(&(r[l1]), s2);

  return r;
}

#endif

void fatal_signal_handler(int signal, void *context)
{
  ScpSession session = (ScpSession) context;
  
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

/*
 * Scp2 main
 */
int main(int argc, char **argv)
{
  struct ScpSessionRec session;
  int i;
  int ch;
  ScpFileLocation location;

  ssh_event_loop_initialize();

  scp_init_session(&session);

  ssh_debug_register_callbacks(NULL, scp_warning, scp_debug,
                               (void *)(&session));

  while ((ch = ssh_getopt(argc, argv, "qQdpvnuhS:P:c:D:tf1rO", NULL)) != -1)
    {
      if (!ssh_optval)
        {
          usage();
        }
      switch(ch)
        {
        case 't':
        case 'f':
          /* Scp 1 compatibility mode, this is remote server for ssh 1 scp,
             exec old scp here. */
          {
            ssh_warning("Executing scp1 compatibility.");
            execvp("scp1", argv);
            ssh_fatal("Executing ssh1 in compatibility mode failed.");
          }

          break;
        case '1':
          /* Scp 1 compatibility in the client */
          {
            char **av;
            int j = 0;
            int removed_flag = FALSE;
            
            av = ssh_xcalloc(argc, sizeof(char *));
            ssh_warning("Executing scp1 compatibility.");
            for (i=0 ; i < argc ; i++)
              {
                
                SSH_DEBUG(5, ("argv[%d] = %s", i, argv[i]));

                /* skip first "-1" argument */
                if (strcmp("-1", argv[i]) || removed_flag)
                  {
                    av[j] = argv[i];
                    j++;
                  }
                else
                  {
                    removed_flag = TRUE;
                  }
                
              }
            
            execvp("scp1", av);
            ssh_fatal("Executing ssh1 in compatibility mode failed.");
          }
          
          break;
        case 'p':
          session.preserve_flag = TRUE;
          break;
        case 'r':
          session.recurse_flag = TRUE;
          session.need_dst_dir = TRUE;
          break;
        case 'P':
          session.port = atoi(ssh_optarg);
          if ((session.port <= 0) || (session.port > 65535))
            usage();
          break;
        case 'c':
          if (session.cipher_list == NULL)
            {
              session.cipher_list_last = scp_new_cipher_item(ssh_optarg);
              session.cipher_list_last->next = NULL;
              session.cipher_list = session.cipher_list_last;
            }
          else
            {
              session.cipher_list_last->next = scp_new_cipher_item(ssh_optarg);
              session.cipher_list_last = session.cipher_list_last->next;
              session.cipher_list_last->next = NULL;
            }
          break;
        case 'S':
          ssh_xfree(session.ssh_path);
          session.ssh_path = ssh_xstrdup(ssh_optarg);
          ssh_xfree(session.ssh1_path);
          session.ssh1_path = ssh_xstrdup(ssh_optarg);
          break;
        case 'd':
          session.need_dst_dir = TRUE;
          break;
        case 'D':
          session.debug_flag = ssh_xstrdup(ssh_optarg);
          ssh_debug_set_level_string(session.debug_flag);
          session.verbose = TRUE;
          break;
        case 'v':
          session.debug_flag = ssh_xstrdup("2");
          ssh_debug_set_level_string(session.debug_flag);
          session.verbose =TRUE;
          break;
        case 'q':
          session.quiet = TRUE;
          session.nostat = TRUE;
          break;
        case 'Q':
          session.nostat = TRUE;
          break;
        case 'u':
          session.unlink_flag = TRUE;
          break;
        case 'n':
          session.do_not_copy = TRUE;
          break;
        case 'h':
          usage();
          break;
        case 'O':
          session.use_ssh1 = TRUE;
          break;
        default:
          usage();
        }
    }

  ssh_register_signal(SIGHUP, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGINT, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGILL, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGABRT, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGFPE, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGBUS, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGSEGV, fatal_signal_handler, (void *)&session);
  ssh_register_signal(SIGTERM, fatal_signal_handler, (void *)&session);
  
  if (isatty(fileno(stdout)))
    session.have_tty = TRUE;
  
  if (session.have_tty == FALSE)
    {
      session.nostat = TRUE;
      session.quiet = TRUE;
    }
  
  argc -= ssh_optind;
  argv += ssh_optind;

  if (argc < 2)
    usage();

  /* Parse source locations */
  for (i = 0; i < (argc - 1); i++)
    {
      location = scp_parse_location_string(argv[i]);

      if (location == NULL)
        usage();
      if (location->port == 0)
        {
          location->port = session.port;
        }

      /* Some sanity checks. */
      if (strlen(location->file) < 1)
        {
          usage();
        }
      else if (!session.recurse_flag)
        {
          char *hlp = strrchr(location->file, '/');
          if (hlp)
            {
              hlp++;
              if (*hlp == '\000')
                usage();
            }
        }

      if (session.src_list == NULL)
        {
          session.src_list = session.src_list_tail = location;
        }
      else
        {
          session.src_list_tail->next = location;
          session.src_list_tail = session.src_list_tail->next;
        }
    }

  /* Parse destination locations */
  location = scp_parse_location_string(argv[i]);

  if (location == NULL)
    usage();
  if (location->port == 0)
    {
      location->port = session.port;
    }

  if (strlen(location->file) < 1)
    {
      ssh_xfree(location->file);
      location->file = ssh_xstrdup(".");
    }
  session.dst_location = location;

  if (session.src_list != session.src_list_tail)
    session.need_dst_dir = 1;

  if (session.dst_location->host == NULL)
    session.dst_is_local = 1;
  else
    session.dst_is_local = 0;

  exit(scp_execute(&session));
}

/*
 * Print usage information.
 */
void usage()
{
  fprintf(stderr, "usage: scp [-D debug_level_spec] [-d] [-p] [-n] [-u] "
                  "[-v] [-1]\n");
  fprintf(stderr, "           [-c cipher] [-S ssh2-path] [-h] "
                  "[-P ssh2-port]\n");
  fprintf(stderr, "           [[user@]host[#port]:]file ...\n");
  fprintf(stderr, "           [[user@]host[#port]:]file_or_dir\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -D debug_level_spec  Set debug level.\n");
  fprintf(stderr, "  -d                   Force target to be a directory.\n");
  fprintf(stderr, "  -q                   Make scp quiet (doesn't show "
                  "progress indicator).\n");
  fprintf(stderr, "  -p                   Preserve file attributes and "
                  "timestamps.\n");
  fprintf(stderr, "  -n                   Show what would've been done "
                  "without actually copying\n");
  fprintf(stderr, "                       any files.\n");
  fprintf(stderr, "  -u                   Remove source-files after "
                  "copying.\n");
  fprintf(stderr, "  -v                   Verbose mode; equal to `-D 2'.\n");
  fprintf(stderr, "  -1                   Engage scp1 compatibility.\n");
  fprintf(stderr, "  -c cipher            Select encryption algorithm. "
                  "Multiple -c options are \n");
  fprintf(stderr, "                       allowed and a single -c flag "
                  "can have only one cipher.\n");
  fprintf(stderr, "  -S ssh2-path         Tell scp2 where to find ssh2.\n");
  fprintf(stderr, "  -P ssh2-port         Tell scp2 which port sshd2 "
                  "listens on the remote machine.\n");
  fprintf(stderr, "  -h                   Display this help.\n");
  fprintf(stderr, "\n");
  exit(SCP_ERROR_USAGE);
}

void scp_init_session(ScpSession session)
{
  session->verbose = FALSE;
  session->quiet = FALSE;
  session->nostat = FALSE;
  session->have_tty = FALSE;
  session->debug_flag = NULL;
  session->preserve_flag = FALSE;
  session->recurse_flag = FALSE;
  session->unlink_flag = FALSE;
  session->child_pid = 0;
  session->port = 0;
  session->do_not_copy = FALSE;
  session->need_dst_dir = FALSE;
  session->dst_is_dir = FALSE;
  session->dst_is_file = FALSE;
  session->dst_is_local = FALSE;
  session->ssh_path = ssh_xstrdup("ssh2");
  session->ssh1_path = ssh_xstrdup("ssh1");
  session->use_ssh1 = FALSE;
  session->cipher_list = NULL;
  session->cipher_list_last = NULL;
  session->dst_client = NULL;
  session->dst_local_client = NULL;
  session->dst_local_server = NULL;
  session->dst_remote_client = NULL;
  session->src_local_client = NULL;
  session->src_local_server = NULL;
  session->src_remote_client = NULL;
  session->src_remote_host = NULL;
  session->src_remote_port = -1;
  session->src_remote_user = NULL;
  session->src_list = NULL;
  session->src_list_tail = NULL;
  session->dst_location = NULL;
  session->current_dst_file = NULL;
  session->current_src_is_local = FALSE;
  session->current_src_location = NULL;
  session->timeout_is_fatal = FALSE;
  session->timeout_triggered = FALSE;
  session->tmp_handle = NULL;
  session->tmp_status = 0;
  session->remote_file_name = NULL;
  session->remote_file_long_name = NULL;
  session->tmp_attributes = NULL;
  session->tmp_attributes_ok = FALSE;
  session->tmp_data = NULL;
  session->tmp_data_len = 0;
  session->callback_fired = FALSE;
  session->error = 0;
  
  return;
}

void scp_print_location_info(ScpFileLocation location)
{
  fprintf(stderr, "    Location data: (%p)\n", location);
  if (location != NULL)
    {
      fprintf(stderr, "      user = ");
      if (location->user)
        fprintf(stderr, "\"%s\"\n", location->user);
      else
        fprintf(stderr, "NULL\n");
      fprintf(stderr, "      host = ");
      if (location->host)
        fprintf(stderr, "\"%s\"\n", location->host);
      else
        fprintf(stderr, "NULL\n");
      fprintf(stderr, "      file = ");
      if (location->file)
        fprintf(stderr, "\"%s\"\n", location->file);
      else
        fprintf(stderr, "NULL\n");
      fprintf(stderr, "      port = %d\n", location->port);
      fprintf(stderr, "      next = %p\n", location->next);
      fprintf(stderr, "      contains_wildcards = %s\n",
              location->contains_wildcards ? "TRUE" : "FALSE");
      fprintf(stderr, "      is_dir = %d\n", location->is_dir);
      fprintf(stderr, "      dir_mask = ");
      if (location->dir_mask)
        fprintf(stderr, "\"%s\"\n", location->dir_mask);
      else
        fprintf(stderr, "NULL\n");
    }
  return;
}

void scp_print_session_info(ScpSession session)
{
  fprintf(stderr, "Session data: (%p)\n", session);
  fprintf(stderr, "  debug_flag         = ");
  if (session->debug_flag)
    fprintf(stderr, "\"%s\"\n", session->debug_flag);
  else
    fprintf(stderr, "NULL\n");
          
  fprintf(stderr, "  verbose            = %d\n", session->verbose);
  fprintf(stderr, "  preserve_flag      = %d\n", session->preserve_flag);
  fprintf(stderr, "  port               = %d\n", session->port);
  fprintf(stderr, "  need_dst_dir       = %d\n", session->need_dst_dir);
  fprintf(stderr, "  dst_is_dir         = %d\n", session->dst_is_dir);
  fprintf(stderr, "  dst_is_file        = %d\n", session->dst_is_file);
  fprintf(stderr, "  dst_is_local       = %d\n", session->dst_is_local);
  fprintf(stderr, "  ssh_path           = \"%s\"\n", session->ssh_path);
  fprintf(stderr, "  ssh1_path          = \"%s\"\n", session->ssh1_path);
  fprintf(stderr, "  dst_local_client   = %p\n", session->dst_local_client);
  fprintf(stderr, "  dst_local_server   = %p\n", session->dst_local_server);
  fprintf(stderr, "  dst_remote_client  = %p\n", session->dst_remote_client);
  fprintf(stderr, "  src_local_client   = %p\n", session->src_local_client);
  fprintf(stderr, "  src_local_server   = %p\n", session->src_local_server);
  fprintf(stderr, "  src_remote_client  = %p\n", session->src_remote_client);
  fprintf(stderr, "  src_list           = %p\n", session->src_list);
  if (session->src_list)
    {
      ScpFileLocation loc = session->src_list;
      while (loc != NULL)
        {
          scp_print_location_info(loc);
          loc = loc->next;
        }
    }
  fprintf(stderr, "  src_list_tail      = %p\n", session->src_list_tail);
  fprintf(stderr, "  dst_location       = %p\n", session->dst_location);
  scp_print_location_info(session->dst_location);
  fprintf(stderr, "  current_dst_file   = ");
  if (session->current_dst_file != NULL)
    fprintf(stderr, "\"%s\"\n", session->current_dst_file);
  else
    fprintf(stderr, "NULL\n");
  fprintf(stderr, "  current_src_location = %p\n", 
          session->current_src_location);
  scp_print_location_info(session->current_src_location);
  fprintf(stderr, "  current_src_is_local = %d\n", 
          session->current_src_is_local);
  fprintf(stderr, "  timeout_is_fatal   = %d\n", session->timeout_is_fatal);
  fprintf(stderr, "  timeout_triggered  = %d\n", session->timeout_triggered);
  return;
}

void scp_debug(const char *msg, void *context)
{
  ScpSession session = (ScpSession)context;
  clearerr(stderr); /*XXX*/
  if (!session->quiet && session->debug_flag)
    fprintf(stderr, "debug: %s\r\n", msg);
  clearerr(stderr); /*XXX*/
}

void scp_warning(const char *msg, void *context)
{
  ScpSession session = (ScpSession)context;
  if (!session->quiet)
    fprintf(stderr, "warning: %s\r\n", msg);
}

ScpCipherName scp_new_cipher_item(char *name)
{
  ScpCipherName r;

  r = (ScpCipherName)ssh_xcalloc(1, sizeof (struct ScpCipherNameRec));
  r->name = ssh_xstrdup(name);
  r->next = NULL;
  return r;
}

/*
 * Creates and allocates a ScpFileLocation-struct.
 * Returns pointer to malloced struct.
 */
ScpFileLocation scp_file_location_allocate(void)
{
  ScpFileLocation rec;

  rec = ssh_xcalloc(1, sizeof(struct ScpFileLocationRec));

  rec->user = NULL;
  rec->host = NULL;
  rec->file = NULL;
  rec->port = 0;
  rec->next = NULL;
  rec->contains_wildcards = FALSE;
  rec->is_dir = -1;
  rec->dir_mask = NULL;
  rec->dir_attrs = NULL;
  
  return rec;
}

/*
 * Duplicate a ScpFileLocation-struct. Returns pointer to malloced
 * struct.
 */
ScpFileLocation scp_file_location_dup(ScpFileLocation rec)
{
  ScpFileLocation dup;

  dup = ssh_xcalloc(1, sizeof(struct ScpFileLocationRec));

  dup->user = rec->user ? ssh_xstrdup(rec->user) : NULL;
  dup->host = rec->host ? ssh_xstrdup(rec->host) : NULL;
  dup->file = rec->file ? ssh_xstrdup(rec->file) : NULL;
  dup->port = rec->port;
  dup->next = rec->next;
  dup->contains_wildcards = rec->contains_wildcards;
  dup->is_dir = rec->is_dir;
  dup->dir_mask = rec->dir_mask ?
    ssh_xstrdup(rec->dir_mask) : NULL;
  dup->dir_attrs = rec->dir_attrs ?
    ssh_file_attributes_dup(rec->dir_attrs) : NULL;
  return dup;
}

/*
 * Free a ScpFileLocation-struct.
 */
void scp_file_location_free(ScpFileLocation rec)
{
  if (rec == NULL)
    return;
  
  ssh_xfree(rec->user);
  ssh_xfree(rec->host);
  ssh_xfree(rec->file);
  ssh_xfree(rec->dir_attrs);
  ssh_xfree(rec);
}

/*
 * Expands wildcards (currently only '*?'). loc_list_start will be
 * used to store the start of the made list, and loc_list_tail the
 * end. basepath is the path where expanding will
 * begin. orig_glob_pattern holds the original glob pattern
 * given. Function returns FALSE if successful, TRUE otherwise. This
 * function is recursive.
 */
Boolean scp_expand_wildcards(ScpFileLocation *loc_list_start,
                             ScpFileLocation *loc_list_tail,
                             char *basepath,
                             char *orig_glob_pattern,
                             ScpSession session)
{
  char *temp_filename, *hlp, *orig_filename;
  ScpFileLocation list_start = NULL, list_tail = NULL;
  ScpFileLocation *new_loc_list_start = NULL, *new_loc_list_tail = NULL;
  Boolean found_expansion = FALSE;
  SshFileHandle handle;
  
  SSH_PRECOND(basepath && orig_glob_pattern);
  SSH_PRECOND(loc_list_start && loc_list_tail);
  SSH_PRECOND(!strncmp((*loc_list_start)->file, basepath, strlen(basepath)));
  SSH_PRECOND((*loc_list_start)->next == NULL);

  /* Only investigate the unexpanded end of the filename */
  orig_filename = ssh_xstrdup((*loc_list_start)->file);
  temp_filename = &orig_filename[strlen(basepath)];

  hlp = strchr(temp_filename, '/');
  
  if (hlp)
    {
      *hlp = '\0';
      hlp++;
    }
  
  /* the filehandle is stored in session->tmp_handle */
  if (scp_file_opendir(session, session->src_remote_client,
                       basepath))
    {
      ssh_xfree(orig_filename);
      return TRUE;
    }

  /* Save handle from being overwritten by calls to scp_file_opendir,
     for instance. */
  handle = session->tmp_handle;
  
  /* Allocate space for pointers. */
  new_loc_list_start =
    ssh_xcalloc(1, sizeof(ScpFileLocation *));
  new_loc_list_tail =
    ssh_xcalloc(1, sizeof(ScpFileLocation *));

  while(!scp_file_readdir(session, handle))
    {
      /* After a scp_file_readdir() call,
         session->tmp_attributes_ok tells whether
         session->tmp_attributes is ok
         (surprisingly). session->remote_file_name and
         session->remote_file_long_name and session->error are
         also set.*/
      if (session->tmp_attributes_ok) 
        {
          char *full_filename;
          int is_dir = 0;
          
          /* Discard if "." or ".." */
          if ((session->tmp_attributes->permissions & S_IFMT)
              == S_IFDIR)
            {
              char *tempdir;
                      
              if ((tempdir = strrchr(session->remote_file_name, '/'))
                  == NULL)
                tempdir = session->remote_file_name;
                      
              if (!strcmp(tempdir, ".") || !strcmp(tempdir, ".."))
                continue;

              is_dir = 1;
            }
          
          full_filename =
            str_concat(basepath, session->remote_file_name);
                  
          /* if filename matches the whole pattern,
             it should be put straight in the list.*/
          /* XXX should match even if orig_glob_pattern ended with a
             '/' */
          if (ssh_match_pattern(full_filename,
                                orig_glob_pattern))
            {
              *new_loc_list_start =
                scp_file_location_dup(*loc_list_start);

              ssh_xfree((*new_loc_list_start)->file);

              (*new_loc_list_start)->file =
                ssh_xstrdup(full_filename);
                      
              (*new_loc_list_start)->contains_wildcards = FALSE;

              (*new_loc_list_start)->is_dir = is_dir;
              
              /* Append. (If list's first item, initialize.) */
              if (list_start == NULL)
                {
                  list_start = *new_loc_list_start;
                  list_tail = list_start;
                }
              else
                {
                  list_tail->next = *new_loc_list_start;
                  list_tail = list_tail->next;
                }
              
              found_expansion = TRUE;
              ssh_xfree(full_filename);
              continue;
            }

          /* Filename still contains wildcards, that need
             to be expanded. */
          if ((session->tmp_attributes->permissions & S_IFMT)
              == S_IFDIR)
            {
              if (ssh_match_pattern(session->remote_file_name,
                                    temp_filename))
                {
                  unsigned int len;
                          
                  /* Check if we need to add a '/' to the end */
                  len = strlen(full_filename);
                          
                  if (full_filename[len - 1] != '/')
                    {
                      full_filename =
                        ssh_xrealloc(full_filename, len + 2);
                      full_filename[len] = '/';
                      full_filename[len + 1] = '\0';
                    }

                  *new_loc_list_start =
                    scp_file_location_dup(*loc_list_start);
                  ssh_xfree((*new_loc_list_start)->file);

                  (*new_loc_list_start)->file =
                    str_concat(full_filename, hlp);
                          
                  (*new_loc_list_start)->contains_wildcards =
                    scp_check_wildcards(hlp);
                              
                  if (!scp_expand_wildcards(new_loc_list_start,
                                            new_loc_list_tail,
                                            full_filename,
                                            orig_glob_pattern,
                                            session))
                    {
                      found_expansion = TRUE;
                      /* Append. (If list's first item, initialize.) */
                      if (list_start == NULL)
                        {
                          list_start = *new_loc_list_start;
                          list_tail = *new_loc_list_tail;
                        }
                      else
                        {
                          list_tail->next = *new_loc_list_start;
                          list_tail = *new_loc_list_tail;
                        }
                    }
                  else
                    {
                      scp_file_location_free(*new_loc_list_start);
                      ssh_xfree(full_filename);
                    }
                }
            }
        }
    }

  ssh_xfree(orig_filename);
  ssh_file_client_close(handle, NULL, NULL);
  ssh_xfree(new_loc_list_start);
  ssh_xfree(new_loc_list_tail);
  
  if (!found_expansion)
    return TRUE;
  
  *loc_list_start = list_start;
  *loc_list_tail = list_tail;
  
  return FALSE;
}

/*
 * This is used to traverse directory-paths recursively. It
 * starts from the path specified in loc_list_start, and stores all
 * file names to this list structure. When this function encounters a
 * directory, it calls itself. basepath is used to give this function
 * information about the path where the recursion started. found
 * filename is stored to fileloc->file. In case of an error, which
 * causes this function to fail so that no files are put to the list,
 * it returns TRUE. Otherwise, it returns FALSE.
 */
Boolean scp_recurse_directories(ScpFileLocation *loc_list_start,
                                ScpFileLocation *loc_list_tail,
                                ScpSession session,
                                SshFileClient src_client)
{
  ScpFileLocation list_start = NULL, list_tail = NULL;
  ScpFileLocation *new_loc_list_start = NULL, *new_loc_list_tail = NULL;
  ScpFileLocation temp_loc = NULL;
  SshFileHandle handle;
  Boolean found_expansion = FALSE; 
  
  SSH_PRECOND(loc_list_start && loc_list_tail);
  SSH_PRECOND((*loc_list_start)->next == NULL);
  SSH_PRECOND(src_client);
  
  /* the filehandle is stored in session->tmp_handle */
  if (scp_file_opendir(session, src_client,
                       (*loc_list_start)->file))
    {
      return TRUE;
    }

  *loc_list_tail = *loc_list_start;
  (*loc_list_start)->is_dir = 1;
  if (session->preserve_flag)
    {
      if (scp_file_lstat(session, (*loc_list_start)->file,
                          src_client))
        {
          (*loc_list_start)->dir_attrs =
          ssh_file_attributes_dup(session->tmp_attributes);
        }
      else
        {
          ssh_warning("lstat failed for directory \"%s\", couldn't get "
                      "file permissions.", (*loc_list_start)->file);
        }
    }
  
  /* Save handle from being overwritten by calls to scp_file_opendir,
     for instance. */
  handle = session->tmp_handle;

  /* Allocate space for pointers. */
  new_loc_list_start =
    ssh_xcalloc(1, sizeof(ScpFileLocation *));
  new_loc_list_tail =
    ssh_xcalloc(1, sizeof(ScpFileLocation *));

  while(!scp_file_readdir(session, handle))
    {
      /* XXX check tmp_attributes->flags */
      /* After a scp_file_readdir() call,
         session->tmp_attributes_ok tells whether
         session->tmp_attributes is ok
         (surprisingly). session->remote_file_name and
         session->remote_file_long_name and session->error are
         also set.*/
      if (session->tmp_attributes_ok) 
        {
          char *full_filename;
          int is_dir = 0;

          /* Discard if "." or ".." */
          if ((session->tmp_attributes->permissions & S_IFMT)
              == S_IFDIR)
            {
              char *tempdir;
                      
              if ((tempdir = strrchr(session->remote_file_name, '/'))
                  == NULL)
                tempdir = session->remote_file_name;
                      
              if (!strcmp(tempdir, ".") || !strcmp(tempdir, ".."))
                continue;

              found_expansion = TRUE;          
              is_dir = 1;
            }

          full_filename =
            str_concat_3((*loc_list_start)->file, "/",
                         session->remote_file_name);

          if ((session->tmp_attributes->permissions & S_IFMT)
              == S_IFREG)
            {
              /* store filenames etc. */
              temp_loc = scp_file_location_dup(*loc_list_start);
              ssh_xfree(temp_loc->file);
              temp_loc->file = full_filename;
              temp_loc->is_dir = 0;
              if (list_start == NULL)
                {
                  list_start = temp_loc;
                  list_tail = list_start;
                }
              else
                {
                  list_tail->next = temp_loc;
                  list_tail = list_tail->next;
                }
              
              found_expansion = TRUE;          
            }
          
          /* XXX what if permissions doesn't contain everything we need?
             We should check tmp_attributes->flags for this. */
          if ((session->tmp_attributes->permissions & S_IFMT)
              == S_IFDIR)
            {
              *new_loc_list_start =
                scp_file_location_dup(*loc_list_start);
              ssh_xfree((*new_loc_list_start)->file);
              
              (*new_loc_list_start)->file = full_filename;

              if (session->preserve_flag)  
                (*new_loc_list_start)->dir_attrs =
                  ssh_file_attributes_dup(session->tmp_attributes);
              
              if (!scp_recurse_directories(new_loc_list_start,
                                           new_loc_list_tail,
                                           session,
                                           src_client))
                {
                  found_expansion = TRUE;
                  /* Append. (If list's first item, initialize.) */
                  if (list_start == NULL)
                    {
                      list_start = *new_loc_list_start;
                      list_tail = *new_loc_list_tail;
                    }
                  else
                    {
                      list_tail->next = *new_loc_list_start;
                      list_tail = *new_loc_list_tail;
                    }
                }
              else
                {
                  scp_file_location_free(*new_loc_list_start);
                }
            }
        }
    }

  ssh_file_client_close(handle, NULL, NULL);
  ssh_xfree(new_loc_list_start);
  ssh_xfree(new_loc_list_tail);
  
  if (!found_expansion)
    return TRUE;
  
  (*loc_list_start)->next = list_start;
  *loc_list_tail = list_tail;
  
  return FALSE;
}

/*
 * Takes in a string str that is of form
 * [[user@]host[#port]:]file and parses it to tokens which contain a
 * file's location as (optional) username, (optional) hostname,
 * (optional) port and (required) filename. Returns a pointer to a
 * valid calloced ScpFileLocation struct if successful, otherwise
 * returns NULL. If port number wasn't valid, loc->port will
 * be 0.
 */
ScpFileLocation scp_parse_location_string(char *str)
{
  ScpFileLocation loc;
  char *hlp;

  loc = scp_file_location_allocate();

  if ((!str) || (!(*str)))
    goto error_ret;

  hlp = strchr(str, ':');
  if (!hlp)
    {
      /* It's local */
      loc->file = ssh_xstrdup(str);
      loc->user = NULL;
      loc->host = NULL;
      loc->next = NULL;
    } else {
      /* It's remote */
      *hlp = '\000';
      hlp++;
      loc->file = ssh_xstrdup(hlp);
      hlp = strchr(str, '@');
      if (hlp)
        {
          *hlp = '\000';
          hlp++;
          if (!hlp)
            goto error_ret;

          loc->user = ssh_xstrdup(str);
          str = hlp;
        } else {
          loc->user = NULL;      
        }
      hlp = strchr(str, '#');
      if (hlp)
        {
          *hlp = '\000';
          hlp++;
          loc->port = atoi(hlp);
          if ((loc->port < 1) || (loc->port > 65535))
            goto error_ret;
        }
      else
        {
          loc->port = 0;
        }
      if (!(*str))
        goto error_ret;
      loc->host = ssh_xstrdup(str);
    }

  /* check if wildcards are present. If there is, change
   * loc->contains_wildcards to TRUE.
   */
  loc->contains_wildcards = scp_check_wildcards(loc->file);
  
  return loc;

 error_ret:
  if (loc->user)
    ssh_xfree(loc->user);
  if (loc->host)
    ssh_xfree(loc->host);
  if (loc->file)
    ssh_xfree(loc->file);
  ssh_xfree(loc);
  return NULL;
}

#define SSH_ARGV_SIZE   64

SshFileClient scp_open_remote_connection(ScpSession session,
                                         char *host,
                                         char *user, 
                                         int port)
{
  SshFileClient client;
  SshStream client_stream;
  char *ssh_argv[SSH_ARGV_SIZE];
  char port_buf[16];
  int i;
  ScpCipherName cipher;

  assert(host != NULL);
  assert(session != NULL);
  assert(session->ssh_path != NULL);
  assert(session->ssh1_path != NULL);

  i = 0;

  if (! session->use_ssh1)
    ssh_argv[i++] = session->ssh_path;
  else 
    ssh_argv[i++] = session->ssh1_path;

  if (user != NULL)
    {
      ssh_argv[i++] = "-l";
      ssh_argv[i++] = user;
    }
  if (port > 0)
    {
      snprintf(port_buf, sizeof (port_buf), "%d", port);
      ssh_argv[i++] = "-p";
      ssh_argv[i++] = port_buf;
    }
  if (session->verbose)
    ssh_argv[i++] = "-v";

  if (! session->use_ssh1)
    {
      ssh_argv[i++] = "-o";
      ssh_argv[i++] = "passwordprompt %U@%H's password: ";
      ssh_argv[i++] = "-o";
      ssh_argv[i++] = "nodelay yes";
    }
  else
    {
      ssh_argv[i++] = "-o";
      ssh_argv[i++] = "PasswordPromptHost yes";
      ssh_argv[i++] = "-o";
      ssh_argv[i++] = "PasswordPromptLogin yes";
    }

  if (! session->use_ssh1)
    {
      for (cipher = session->cipher_list; 
           cipher != NULL; 
           cipher = cipher->next)
        {
          assert(i < SSH_ARGV_SIZE);
          
          ssh_argv[i++] = "-c";
          ssh_argv[i++] = cipher->name;
        }
    }
  else
    {
      if (session->cipher_list != NULL)
        {
          ssh_argv[i++] = "-c";
          ssh_argv[i++] = session->cipher_list->name;
        }
    }

  ssh_argv[i++] = host;

  if (! session->use_ssh1)
    {
      ssh_argv[i++] = "-s";
      ssh_argv[i++] = "sftp";
    }
  else
    {
      ssh_argv[i++] = "sftp-server";
    }

  ssh_argv[i] = NULL;

  assert(i < SSH_ARGV_SIZE);
     
  if (session->verbose)
    {
      for (i = 0; ssh_argv[i]; i++)
        SSH_DEBUG(2, ("argv[%d] = %s", i, ssh_argv[i]));
    }
  
  switch (ssh_pipe_create_and_fork(&client_stream, NULL))
    {
    case SSH_PIPE_ERROR:
      ssh_fatal("ssh_pipe_create_and_fork() failed");
    
    case SSH_PIPE_PARENT_OK:      
      /* Try to wrap this as the server */

      session->child_pid = ssh_pipe_get_pid(client_stream);
      client = ssh_file_client_wrap(client_stream);
      return client;
    
    case SSH_PIPE_CHILD_OK:
      execvp(ssh_argv[0], ssh_argv);
      fprintf(stderr, "Executing ssh2 failed. Command:'");
      for (i = 0;ssh_argv[i] != NULL; i++)
        fprintf(stderr," %s", ssh_argv[i]);

      fprintf(stderr,"' System error message: '%s'\r\n", strerror(errno));
      exit(254);
    }  
  return NULL;
}

/*
 * Copies information about a remote connection to be
 * used in connecting.
 */
void scp_set_src_remote_location(ScpSession session, 
                                 char *host, 
                                 int port, 
                                 char *user)
{
  assert(host != NULL);

  if (session->src_remote_host != NULL)
    ssh_xfree(session->src_remote_host);
  if (session->src_remote_user != NULL)
    ssh_xfree(session->src_remote_user);
  session->src_remote_host = ssh_xstrdup(host);
  session->src_remote_user = user ? ssh_xstrdup(user) : NULL;
  session->src_remote_port = port;
}

/*
 * This function checks whether arguments are ok for
 * remote connection. Return TRUE, if they are.
 */
Boolean scp_set_src_is_remote_location_ok(ScpSession session, 
                                          char *host, 
                                          int port, 
                                          char *user)
{
  if ((session->src_remote_client == NULL) ||
      (session->src_remote_host == NULL) ||
      (strcmp(session->src_remote_host, host) != 0) ||
      (session->src_remote_port != port) ||
      ((session->src_remote_user == NULL) && (user != NULL)) ||
      ((session->src_remote_user != NULL) && (user == NULL)))
    return FALSE;
      
  if (((session->src_remote_user == NULL) && (user == NULL)) ||
      (strcmp(session->src_remote_user, user) == 0))
    return TRUE;

  return FALSE;
}

/*
 * Extract a filename from a path. Return NULL if `pathname' is
 * invalid.
 */
char *scp_file_basename(char *pathname)
{
  char *r;

  r = strrchr(pathname, '/');
  if (r == NULL)
    return ssh_xstrdup(pathname);
  r++;
  if (*r != '\000')
    return ssh_xstrdup(r);
  return NULL;
}

void scp_set_next_src_location(void *context)
{
  ScpSession session = (ScpSession)context;
  SshFileAttributes attrs;
  ScpFileLocation *list_start = NULL, *list_tail = NULL, tmp;
  ScpFileLocation to_be_deleted;
  char *temp_filename = NULL, *basepath = NULL;
  
  if (session->current_src_location)
    {
      if (session->current_src_location->user != NULL)
        ssh_xfree(session->current_src_location->user);
      if (session->current_src_location->host != NULL)
        ssh_xfree(session->current_src_location->host);
      if (session->current_src_location->file != NULL)
        ssh_xfree(session->current_src_location->file);
      ssh_xfree(session->current_src_location);
    }

  /* Here we do wildcard-expansion*/
  if (session->src_list && session->src_list->contains_wildcards)
    {
      char *basepath = NULL;
      
      /* host has to be remote, not local, otherwise the shell
         would've parsed the wildcards for us.*/
      if (!session->src_list->host)
        {
          SSH_DEBUG(4, ("Not expanding wildcards from local source file " \
                        "\"%s\".", session->src_list->file));
          goto no_wildcard_expansion;
        }

      list_start = ssh_xmalloc(sizeof(ScpFileLocation *));
      list_tail = ssh_xmalloc(sizeof(ScpFileLocation *));
      

      to_be_deleted = session->src_list;
      if (!scp_set_src_is_remote_location_ok(session,
                                             session->src_list->host,
                                             session->src_list->port,
                                             session->src_list->user))
        {
          
          if (session->src_remote_client != NULL)
            {
              ssh_file_client_destroy(session->src_remote_client);
              session->src_remote_client = NULL;
            }
          session->src_remote_client =
            scp_open_remote_connection(session,
                                       session->src_list->host, 
                                       session->src_list->user,
                                       session->src_list->port);
          scp_set_src_remote_location(session, 
                                      session->src_list->host,
                                      session->src_list->port,
                                      session->src_list->user);
        }
      
      if (session->src_remote_client == NULL)
        ssh_fatal("Cannot reach the source location.");
      scp_abort_if_remote_dead(session, session->src_remote_client);
      
      
      *list_start =
        scp_file_location_dup(session->src_list);

      if (session->src_list->file[0] == '/')
        basepath = ssh_xstrdup("/");
      else
        basepath = ssh_xstrdup("");
      
      /* Expand. (NOTE: this is a recursive function) */
      if (!scp_expand_wildcards(list_start, list_tail,
                                basepath, session->src_list->file,
                                session))
        {
          tmp = session->src_list->next;
          session->src_list = *list_start;
          (*list_tail)->next = tmp;
          /* XXX free memory */
        }
      else
        {
          ssh_warning("No wildcard expansions found for '%s'.",
                      to_be_deleted->file);
          /* Move to next. */
          session->src_list = session->src_list->next;
        }

      /* Free memory. This entry is no longer needed, as it is now
         expanded or found to be unusable. */
      scp_file_location_free(to_be_deleted);
    }

 no_wildcard_expansion:
  
  if (!session->recurse_flag)
    goto no_dir_recursion;
  
  /* Recurse directories. */
  /* Check whether entry is uninitialized or directory. */
  if (session->src_list && session->src_list->is_dir != 0 &&
      session->src_list->dir_mask == NULL && session->recurse_flag)
    {
      SshFileClient src_client;
      
      if (!session->src_list->host)
        {
          session->current_src_is_local = TRUE;   
          src_client = session->src_local_client;
        }
      else
        {
          
          /* Open connection */
          if (!scp_set_src_is_remote_location_ok(session,
                                                 session->src_list->host,
                                                 session->src_list->port,
                                                 session->src_list->user))
            {
              if (session->src_remote_client != NULL)
                {
                  ssh_file_client_destroy(session->src_remote_client);
                  session->src_remote_client = NULL;
                }

              session->src_remote_client =
                scp_open_remote_connection(session,
                                           session->src_list->host, 
                                           session->src_list->user,
                                           session->src_list->port);
              scp_set_src_remote_location(session, 
                                          session->src_list->host,
                                          session->src_list->port,
                                          session->src_list->user);
            }
          
          if (session->src_remote_client == NULL)
            ssh_fatal("Cannot reach the source location.");
          scp_abort_if_remote_dead(session, session->src_remote_client);
          src_client = session->src_remote_client;        
        }
      
      /* If it is uninitialized, check it. */
      if (session->src_list->is_dir == -1)
        {
          /* XXX We don't want to follow symlinks. */
          attrs = scp_file_lstat(session, session->src_list->file,
                                 src_client);

          if (attrs)
            if ((attrs->permissions & S_IFMT) == S_IFDIR)
              {
                session->src_list->is_dir = 1;
              }
            else
              {
                session->src_list->is_dir = 0;              
                goto no_dir_recursion;
              }
          else
            {
              SSH_DEBUG(2, ("Failed to get attributes of file \"%s\"." \
                            , session->src_list->file));
            }
          
        }
      
      list_start = ssh_xmalloc(sizeof(ScpFileLocation *));
      list_tail = ssh_xmalloc(sizeof(ScpFileLocation *));

      *list_start = scp_file_location_dup(session->src_list);
      
      to_be_deleted = session->src_list;

      temp_filename = ssh_xstrdup(session->src_list->file);

      basepath = strrchr(temp_filename, '/');
      if (basepath)
        {
          *basepath = '\0';
          basepath = ssh_xstrdup(temp_filename);
        }
      else
        {
          basepath = ssh_xstrdup("");
        }
      

      SSH_DEBUG(5, ("Directory mask used in recursion is \"%s\".", \
                    basepath));

      ssh_xfree(temp_filename);
      
      (*list_start)->dir_mask = basepath;
      (*list_start)->next = NULL;
      
      /* Perform directory recursion. After this zzz xxx yyy zap zap */
      if (!scp_recurse_directories(list_start, list_tail,
                                   session, src_client))
        {
          tmp = session->src_list->next;
          session->src_list = *list_start;
          (*list_tail)->next = tmp;
          /* XXX free memory */
        }
      else
        {
          ssh_warning("Couldn't recurse directories for \"%s\".",
                      to_be_deleted->file);
          /* Move to next. */
          session->src_list = session->src_list->next;
        }
      /* Free memory. This entry is no longer needed, as it is now
         expanded or found to be unusable. */
      scp_file_location_free(to_be_deleted);
    }

  /* either src was not a dir or recursion not specified */
 no_dir_recursion:
  
  if (session->src_list == NULL)
    {
      session->src_list_tail = NULL;    
      if (session->src_remote_client != NULL)
        {
          ssh_file_client_destroy(session->src_remote_client);
          session->src_remote_client = NULL;
        }
      return;
    }
  
  session->current_src_location = session->src_list;
  session->src_list = session->src_list->next;
  if (session->src_list == NULL)
    {
      session->src_list_tail = NULL;    
    }
  
  if (session->current_dst_file != NULL)
    {
      ssh_xfree(session->current_dst_file);
      session->current_dst_file = NULL;
    }

  if (session->current_src_location->dir_mask)
    {
      temp_filename =
        ssh_xstrdup(&session->
                    current_src_location->
                    file[strlen(session->
                                current_src_location->dir_mask)]);

      /* Remove excess '/' characters */
      for (;*temp_filename == '/';)
        temp_filename++;

      if (session->dst_location->file[strlen(session->dst_location->file) - 1]
          == '/')
        session->dst_location->file[strlen(session->dst_location->file) - 1] =
          '\0';

      
      session->current_dst_file = 
        str_concat_3(session->dst_location->file,
                     "/",
                     temp_filename);
      SSH_DEBUG(5, ("new destination filename is \"%s\"",
                    session->current_dst_file));
      
    }
  else if (session->dst_is_dir)
    {
      char *hlp = strrchr(session->current_src_location->file, '/');
      /* Remove excess '/' characters */
      if (session->dst_location->file[strlen(session->dst_location->file) - 1]
          == '/')
        session->dst_location->file[strlen(session->dst_location->file) - 1] =
          '\0';
      
      if (hlp == NULL)
        {
          session->current_dst_file = 
            str_concat_3(session->dst_location->file,
                         "/",
                         session->current_src_location->file);
        }
      else
        {
          hlp++;
          session->current_dst_file = 
            str_concat_3(session->dst_location->file,
                         "/",
                         hlp);
        }
    }
  else
    {
      session->current_dst_file = ssh_xstrdup(session->dst_location->file);
    }

  if (session->current_src_location->host == NULL)
    {
      session->current_src_is_local = 1;
      /* Next source file is local */
      return;
    }
  else
    {
      session->current_src_is_local = 0;
    }

  if (!(scp_set_src_is_remote_location_ok(session, 
                                          session->current_src_location->host, 
                                          session->current_src_location->port, 
                                          session->
                                          current_src_location->user)))
    {
      if (session->src_remote_client != NULL)
        {
          ssh_file_client_destroy(session->src_remote_client);
          session->src_remote_client = NULL;
        }
      session->src_remote_client =
        scp_open_remote_connection(session,
                                   session->current_src_location->host, 
                                   session->current_src_location->user,
                                   session->current_src_location->port);
      scp_set_src_remote_location(session, 
                                  session->current_src_location->host,
                                  session->current_src_location->port,
                                  session->current_src_location->user);
      if (session->src_remote_client == NULL)
        ssh_fatal("Cannot reach the source location.");
      scp_abort_if_remote_dead(session, session->src_remote_client);
    }
  /* Next source file is remote and client is now up */
  return;
}

void scp_timeout_callback(void *context)
{
  ScpSession session = (ScpSession)context;

  if (session->timeout_is_fatal)
    ssh_fatal("Operation timed out.");
  session->timeout_triggered++;
  return;
}

void scp_remote_dead_timeout(void *context)
{
  ScpSession session = (ScpSession)context; 

  session->callback_fired = 1;

  /* Destroy remote connection, if any */
  if (session->src_remote_client != NULL)
    {
      ssh_file_client_destroy(session->src_remote_client);
      session->src_remote_client = NULL;
    }

  /* Above doesn't work, if connection is still being made (which is
     the case, if a passphrase or -word is being asked by ssh2), so
     we'll finish the job by siganlling SIGHUP to the client. This is
     a bit kludge-ish. */
  if (session->child_pid != 0)
    {
      SSH_DEBUG(2, ("Connection timed out, killing child process (ssh2, pid " \
                    "%d)...", session->child_pid));
      if (kill(session->child_pid, SIGHUP) != 0)
        {
          SSH_DEBUG(2, ("killing child process did not succeed."));
        }
    }

  ssh_fatal("Connection timed out.");
}

void scp_remote_alive_callback(SshFileClientError error,
                               const char *name,
                               const char *long_name,
                               SshFileAttributes attrs,
                               void *context)
{
  ScpSession session = (ScpSession)context; 

  session->callback_fired = 1;
  if (error != SSH_FX_OK)
    ssh_fatal("Connection lost.");
  ssh_event_loop_abort();
}

void scp_abort_if_remote_dead(ScpSession session, SshFileClient client)
{
  session->callback_fired = 0;
  ssh_file_client_realpath(client, ".", scp_remote_alive_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
}

void scp_is_dst_directory_callback(SshFileClientError error,
                                   SshFileAttributes attributes,
                                   void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  if (error != SSH_FX_OK)
    {
      session->dst_is_dir = 0;
      session->dst_is_file = 0;
    }
  else
    {
      if ((attributes->permissions & S_IFMT) == S_IFDIR)
        {
          session->dst_is_dir = 1;
          session->dst_is_file = 0;
        }
      else
        {
          session->dst_is_dir = 0;
          session->dst_is_file = 1;
        }
    }
  ssh_event_loop_abort();
}

void scp_get_win_dim(int *width, int *height)
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

void scp_kitt(off_t pos, off_t total, int width)
{
  int i, p;

  if (total)
    p = width * pos / total;  
  else
    p = width * 2;
  
  printf("\r|");
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

void scp_file_handle_callback(SshFileClientError error, 
                              SshFileHandle handle, 
                              void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = TRUE;

  ssh_event_loop_abort();
  session->tmp_handle = handle;
  session->tmp_status = error;
  
  return;
}

SshFileHandle scp_file_open(ScpSession session,
                            SshFileClient client,
                            char *file,
                            int flags,
                            SshFileAttributes attributes)
{
  session->callback_fired = 0;
  session->tmp_handle = NULL;
  ssh_file_client_open(client, file, flags, attributes, 
                       scp_file_handle_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_handle;
}

void scp_file_status_callback(SshFileClientError error, void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  ssh_event_loop_abort();  
  session->tmp_status = error;
  return;
}

int scp_file_close(ScpSession session, SshFileHandle handle)
{
  session->callback_fired = 0;
  ssh_file_client_close(handle, scp_file_status_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_status;
}

/* File name return callback */

void scp_file_name_callback(SshFileClientError error, 
                            const char *name, 
                            const char *long_name,
                            SshFileAttributes attributes,
                            void *context)
{
  ScpSession session;
  
  session = (ScpSession) context;
  SSH_PRECOND(!session->callback_fired);
  session->tmp_status = error;
  session->remote_file_name = name ? ssh_xstrdup(name) : NULL;
  session->remote_file_long_name = long_name ? ssh_xstrdup(long_name) : NULL;
  if (attributes && error == SSH_FX_OK)
    {
      if (session->tmp_attributes)
        {
          ssh_xfree(session->tmp_attributes);
          session->tmp_attributes = NULL;
        }
      session->tmp_attributes = ssh_file_attributes_dup(attributes);
      session->tmp_attributes_ok = TRUE;
    }
  else
    {
      session->tmp_attributes_ok = FALSE;
    }
  session->callback_fired = TRUE;
  
  ssh_event_loop_abort();
}


void scp_file_attribute_callback(SshFileClientError error, 
                                 SshFileAttributes attributes,
                                 void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  ssh_event_loop_abort();  
  if (error == SSH_FX_OK)
    {
      if (session->tmp_attributes)
        {
          ssh_xfree(session->tmp_attributes);
          session->tmp_attributes = NULL;
        }
      session->tmp_attributes = ssh_file_attributes_dup(attributes);
      session->tmp_attributes_ok = TRUE;
    }
  else
    {
      session->tmp_attributes_ok = FALSE;
    }
}

SshFileAttributes scp_file_fstat(ScpSession session, 
                                 SshFileHandle handle)
{
  session->callback_fired = FALSE;
  ssh_file_client_fstat(handle, scp_file_attribute_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return (session->tmp_attributes_ok ? (session->tmp_attributes) : NULL);
}

SshFileAttributes scp_file_stat(ScpSession session,
                                const char *name,
                                SshFileClient client)
{
  session->callback_fired = FALSE;
  ssh_file_client_stat(client, name, scp_file_attribute_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return (session->tmp_attributes_ok ? (session->tmp_attributes) : NULL);
}

SshFileAttributes scp_file_lstat(ScpSession session,
                                const char *name,
                                SshFileClient client)
{
  session->callback_fired = FALSE;
  ssh_file_client_lstat(client, name, scp_file_attribute_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return (session->tmp_attributes_ok ? (session->tmp_attributes) : NULL);
}

void scp_file_read_callback(SshFileClientError error,
                            const unsigned char *data,
                            size_t len,
                            void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;
  ssh_event_loop_abort();  
  if (error == SSH_FX_OK)
    {
      session->tmp_data_len = len;
      memcpy(session->tmp_data, data, len);
    }
  else if (error == SSH_FX_EOF)
      {
        session->tmp_data_len = 0;
        session->tmp_data = NULL;
      }
  else
    {
        session->tmp_data_len = -1;
        session->tmp_data = NULL;
      }
  return;
}

#ifdef OLD_FILE_COPY_LOOP
int scp_file_read(ScpSession session, 
                  SshFileHandle handle,
                  off_t offset, 
                  char *buf,
                  size_t bufsize)
{
  session->callback_fired = 0;
  session->tmp_data = buf;
  session->tmp_data_len = bufsize;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  ssh_file_client_read(handle, offset, bufsize, 
                       scp_file_read_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_data_len;
}

int scp_file_write(ScpSession session,
                   SshFileHandle handle, 
                   off_t offset, 
                   char *buf, 
                   size_t bufsize)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  ssh_file_client_write(handle, offset, buf, bufsize, 
                        scp_file_status_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  if (session->tmp_status != SSH_FX_OK)
    return -1;
  else
    return bufsize;
}
#endif /* OLD_FILE_COPY_LOOP */

int scp_file_fsetstat(ScpSession session,
                      SshFileHandle handle,
                      SshFileAttributes attributes)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  ssh_file_client_fsetstat(handle,
                           attributes,
                           scp_file_status_callback,
                           session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  if (session->tmp_status != SSH_FX_OK)
    return 1;
  else
    return 0;
}

int scp_file_remove(ScpSession session,
                    SshFileClient client,
                    const char *name)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  ssh_file_client_remove(client, name, scp_file_status_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);

  return (session->tmp_status != SSH_FX_OK);
}


/* opendir */

Boolean scp_file_opendir(ScpSession session, SshFileClient client,
                         const char *name)
{
  session->callback_fired = FALSE;
  ssh_file_client_opendir(client, name, scp_file_handle_callback, session);
  if (!session->callback_fired)
    {
      ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                           0,
                           scp_remote_dead_timeout,
                           session);

      ssh_event_loop_run();
  
      ssh_cancel_timeouts(scp_remote_dead_timeout, session);  
    }
  
  return (session->tmp_status != SSH_FX_OK); 
}

/* Readdir */

Boolean scp_file_readdir(ScpSession session, SshFileHandle handle)
{
  session->callback_fired = FALSE;
  ssh_file_client_readdir(handle, scp_file_name_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout,
                       session);
      
  if (!session->callback_fired)
    ssh_event_loop_run();
  
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);      

  return (session->tmp_status != SSH_FX_OK); 
}

/* Make directory in the remote end. */
Boolean scp_file_mkdir(ScpSession session, SshFileClient client,
                       const char *name, 
                       SshFileAttributes attributes)
{
  session->callback_fired = FALSE;
  ssh_file_client_mkdir(client, name, attributes,
                        scp_file_status_callback, session);
  if (!session->callback_fired)
    {
      ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                           0,
                           scp_remote_dead_timeout,
                           session);
      ssh_event_loop_run();
      ssh_cancel_timeouts(scp_remote_dead_timeout, session);
    }
      
  return (session->tmp_status != SSH_FX_OK);
}

/*
 * For performance reasons the actual file data copy is done
 * asynchronously with concurrent read and write operations.
 */
void scp_copy_file_write_callback(SshFileClientError error, void *context);
void scp_copy_file_read_callback(SshFileClientError error,
                                 const unsigned char *data,
                                 size_t len,
                                 void *context);
void scp_copy_file_timeout(void *context);
Boolean scp_copy_file(ScpSession session,
                      SshFileHandle src_handle,
                      SshFileHandle dst_handle,
                      off_t file_size,
                      int width);

void scp_copy_file_read_callback(SshFileClientError error,
                                 const unsigned char *data,
                                 size_t len,
                                 void *context)

{
  ScpFileCopyContext fc = (ScpFileCopyContext)context;

  SSH_DEBUG(7, ("error = %d, data = %p, len = %lu",
                (int)error, data, (unsigned long)len));

  if ((fc->state == SCP_FC_ERROR) || (fc->state == SCP_FC_TIMEOUT))
    {
      SSH_DEBUG(5, ("Extra callback from earlier failed operation ignored"));
      return;
    }

  if (error == SSH_FX_OK)
    {
      ssh_buffer_append(&(fc->buffer), data, len);
      if (fc->write_pending == 0)
        {
          fc->write_pending = 
            ((SCP_WRITE_MAX > ssh_buffer_len(&(fc->buffer))) ?
             ssh_buffer_len(&(fc->buffer)) :
             SCP_WRITE_MAX);
          SSH_DEBUG(8, ("Activating write of %lu bytes",
                        (unsigned long)fc->write_pending));
          ssh_file_client_write(fc->dst_handle, 
                                fc->write_offset, 
                                ssh_buffer_ptr(&(fc->buffer)),
                                fc->write_pending,
                                scp_copy_file_write_callback,
                                fc);
          ssh_buffer_consume(&(fc->buffer), fc->write_pending);
        }
      else
        {
          SSH_DEBUG(8, ("Not activating write of %lu bytes, %lu bytes pending",
                        (unsigned long)(ssh_buffer_len(&(fc->buffer))),
                        (unsigned long)fc->write_pending));
        }
      fc->read_offset += len;
      if (((ssh_buffer_len(&(fc->buffer)) + fc->write_pending) > 
           SCP_BUF_SIZE_MAX) &&
          (fc->read_offset < fc->file_size))
        {
          SSH_DEBUG(8, ("Maximum read buffer exceeded; waiting for write"));
          fc->state = SCP_FC_BUFFER_FULL;
        }
      else if (fc->read_offset < fc->file_size)
        {
          SSH_DEBUG(8, ("Reactivating read."));
          ssh_file_client_read(fc->src_handle, 
                               fc->read_offset, 
                               ((SCP_READ_MAX < 
                                 (fc->file_size - fc->read_offset)) ? 
                                SCP_READ_MAX : 
                                (fc->file_size - fc->read_offset)), 
                               scp_copy_file_read_callback,
                               fc);
        }
      else
        {
          SSH_DEBUG(8, ("Read completed.  offset = %lu, size = %lu",
                        (unsigned long)fc->read_offset,
                        (unsigned long)fc->file_size));
          fc->state = SCP_FC_READ_COMPLETE;
        }
      ssh_cancel_timeouts(scp_copy_file_timeout, fc);
      ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                           0,
                           scp_copy_file_timeout,
                           fc);
    }
  else
    {
      ssh_warning("Read failed (%d).", (int)error);
      fc->state = SCP_FC_ERROR;
      scp_set_error(fc->session, SCP_ERROR_READ_ERROR);
      scp_copy_file_timeout(fc);
    }
}

void scp_copy_file_write_callback(SshFileClientError error, void *context)
{
  ScpFileCopyContext fc = (ScpFileCopyContext)context;

  SSH_DEBUG(7, ("error = %d", (int)error));

  if ((fc->state == SCP_FC_ERROR) || (fc->state == SCP_FC_TIMEOUT))
    {
      SSH_DEBUG(5, ("Extra callback from earlier failed operation ignored"));
      return;
    }

  if (error == SSH_FX_OK)
    {
      fc->write_offset += fc->write_pending;
      SSH_ASSERT(fc->write_offset <= fc->file_size);
      fc->write_pending = 0;
      if (!fc->session->nostat)
        scp_kitt(fc->write_offset, fc->file_size, fc->term_width);
      if (ssh_buffer_len(&(fc->buffer)) > 0)
        {
          fc->write_pending = 
            ((SCP_WRITE_MAX > ssh_buffer_len(&(fc->buffer))) ?
             ssh_buffer_len(&(fc->buffer)) :
             SCP_WRITE_MAX);
          SSH_DEBUG(8, ("Reactivating write of %lu bytes",
                        (unsigned long)fc->write_pending));
          ssh_file_client_write(fc->dst_handle, 
                                fc->write_offset, 
                                ssh_buffer_ptr(&(fc->buffer)),
                                fc->write_pending,
                                scp_copy_file_write_callback,
                                fc);
          ssh_buffer_consume(&(fc->buffer), fc->write_pending);
        }
      if (fc->state == SCP_FC_BUFFER_FULL)
        {
          ssh_file_client_read(fc->src_handle, 
                               fc->read_offset, 
                               ((SCP_READ_MAX < 
                                 (fc->file_size - fc->read_offset)) ? 
                                SCP_READ_MAX : 
                                (fc->file_size - fc->read_offset)), 
                               scp_copy_file_read_callback, 
                               fc);
          fc->state = SCP_FC_RUNNING;
        }
      ssh_cancel_timeouts(scp_copy_file_timeout, fc);
      ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                           0,
                           scp_copy_file_timeout,
                           fc);
      if (fc->write_offset == fc->file_size)
        {
          fc->state = SCP_FC_COMPLETE;
          ssh_cancel_timeouts(scp_copy_file_timeout, fc);
          ssh_event_loop_abort();
        }
    }
  else
    {
      ssh_warning("Write failed (%d).", (int)error);
      fc->state = SCP_FC_ERROR;
      scp_set_error(fc->session, SCP_ERROR_READ_ERROR);
      scp_copy_file_timeout(fc);
    }
}

void scp_copy_file_timeout(void *context)
{
  ScpFileCopyContext fc = (ScpFileCopyContext)context;

  SSH_DEBUG(5, ("context = %p", context));

  if (fc->state != SCP_FC_ERROR)
    fc->state = SCP_FC_TIMEOUT;
#if 0
  /*
   * There should be some nice way to abort any pending operations
   * for file handles without calling their callbacks.  Since there
   * is no such thing for now, we leave the context `as is' and
   * all subsequent callbacks are ignored.
   */
#endif
  ssh_event_loop_abort();
}

Boolean scp_copy_file(ScpSession session,
                      SshFileHandle src_handle,
                      SshFileHandle dst_handle,
                      off_t file_size,
                      int width)
{
  ScpFileCopyContext fc;
  Boolean r = FALSE;
  
  SSH_DEBUG(7, ("src_handle = %p dst_handle = %p file_size = %lu",
                src_handle, dst_handle, (unsigned long)file_size));
  fc = ssh_xcalloc(1, sizeof (*fc));
  fc->session = session;
  fc->src_handle = src_handle;
  fc->dst_handle = dst_handle;
  fc->file_size = file_size;
  fc->read_offset = 0;
  fc->write_offset = 0;
  fc->write_pending = 0;
  fc->term_width = width;
  fc->state = SCP_FC_RUNNING;
  ssh_buffer_init(&(fc->buffer));
  ssh_file_client_read(fc->src_handle, 
                       fc->read_offset, 
                       ((SCP_READ_MAX < 
                         (fc->file_size - fc->read_offset)) ? 
                        SCP_READ_MAX : 
                        (fc->file_size - fc->read_offset)), 
                       scp_copy_file_read_callback, 
                       fc);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_copy_file_timeout,
                       fc);
  ssh_event_loop_run();
  r = (fc->state == SCP_FC_COMPLETE);
  ssh_cancel_timeouts(scp_copy_file_timeout, fc);
  if (r)
    {
      ssh_buffer_uninit(&(fc->buffer));
      ssh_xfree(fc);
    }
  return r;
}
/*
 * End of file copy loop
 */

Boolean scp_move_file(ScpSession session,
                      char *src_host,
                      char *src_file,
                      SshFileClient src_client,
                      char *dst_host,
                      char *dst_file,
                      SshFileClient dst_client)
{
  SshFileAttributes src_attributes;
  SshTimeMeasure timer;  
  off_t offset;
  off_t file_len;
  int width, r;
  
  SshFileHandle src_handle = NULL, dst_handle = NULL;
  
  timer = ssh_time_measure_allocate();
  ssh_time_measure_start(timer);

  src_handle = scp_file_open(session, 
                             src_client,
                             src_file,
                             O_RDONLY,
                             NULL);
  if (src_handle == NULL)
    {
      scp_set_error(session, SCP_ERROR_CANNOT_OPEN);
      ssh_warning("Cannot open source file %s%s%s",
                  (src_host != NULL) ? src_host : "",
                  (src_host != NULL) ? ":" : "",
                  src_file);
      goto close_error;
    }
  
  src_attributes = scp_file_fstat(session, src_handle);
  if (src_attributes == NULL) 
    {
      scp_set_error(session, SCP_ERROR_CANNOT_STAT);
      ssh_warning("Cannot stat source file %s%s%s",
                  (src_host != NULL) ? src_host : "",
                  (src_host != NULL) ? ":" : "",
                  src_file);
      goto close_error;
    }
  file_len = src_attributes->size;

  if ((src_attributes->permissions & S_IFMT) != S_IFREG) 
    {
      ssh_warning("Source file %s%s%s is not a regular file",
                  (src_host != NULL) ? src_host : "",
                  (src_host != NULL) ? ":" : "",
                  src_file);
      scp_set_error(session, SCP_ERROR_NOT_REGULAR_FILE);
      goto close_error;
    }

  if (! session->do_not_copy)
    if (session->unlink_flag)
      scp_file_remove(session, dst_client, dst_file);

  if (! session->do_not_copy)
    {
      dst_handle = scp_file_open(session,
                                 dst_client,
                                 dst_file,
                                 O_CREAT | O_TRUNC | O_WRONLY,
                                 NULL);
      if (dst_handle == NULL) 
        {
          ssh_warning("Cannot open destination file %s%s%s",
                      (dst_host != NULL) ? dst_host : "",
                      (dst_host != NULL) ? ":" : "",
                      dst_file);
          scp_set_error(session, SCP_ERROR_CANNOT_CREATE);
          goto close_error;
        }
    }

  offset = 0;

  if (! session->do_not_copy)
    {
      if (!session->nostat) 
        {  
          printf("Transfering %s%s%s -> %s%s%s  (%luk)\n",
                 (src_host != NULL) ? src_host : "",
                 (src_host != NULL) ? ":" : "",
                 src_file,
                 (dst_host != NULL) ? dst_host : "",
                 (dst_host != NULL) ? ":" : "",
                 dst_file,
                 (unsigned long) (file_len >> 10) + 1);
          
          scp_get_win_dim(&width, NULL);
          scp_kitt(0, file_len, width);
        }
    }
  else
    {
      printf("Not transferring %s%s%s -> %s%s%s  (%luk)\n",
             (src_host != NULL) ? src_host : "",
             (src_host != NULL) ? ":" : "",
             src_file,
             (dst_host != NULL) ? dst_host : "",
             (dst_host != NULL) ? ":" : "",
             dst_file,
             (unsigned long) (file_len >> 10) + 1);
    }
  
  /* move the file */
    
  if (! session->do_not_copy)
    {
#ifndef OLD_FILE_COPY_LOOP
      r = scp_copy_file(session, src_handle, dst_handle, file_len, width);
      if (! r)
        goto close_error;
#else /* ! OLD_FILE_COPY_LOOP */
      {
        off_t src_len;
        char data[SCP_BUF_SIZE];

        do {
          src_len = scp_file_read(session, 
                                  src_handle,
                                  offset, 
                                  data,
                                  SCP_BUF_SIZE);
          if (src_len < 0)
            {
              ssh_warning("Read error in file %s%s%s",
                          (src_host != NULL) ? src_host : "",
                          (src_host != NULL) ? ":" : "",
                          src_file);
              scp_set_error(session, SCP_ERROR_READ_ERROR);
              goto close_error;
            }
          
          if (src_len > 0)
            {
              r = scp_file_write(session,
                                 dst_handle, 
                                 offset, 
                                 data, 
                                 src_len);
              if (r != src_len)
                {
                  ssh_warning("Write error in file %s%s%s",
                              (dst_host != NULL) ? dst_host : "",
                              (dst_host != NULL) ? ":" : "",
                              dst_file);
                  scp_set_error(session, SCP_ERROR_WRITE_ERROR);
                  goto close_error;
                }
              offset += src_len;
              
              if (!session->nostat)
                scp_kitt(offset, file_len, width);
            }
        } while (src_len == SCP_BUF_SIZE);
      }
#endif /* OLD_FILE_COPY_LOOP */

      if (!session->nostat > 0)
        {
          SshUInt64 time_sec;
          SshUInt32 time_nsec;
          int minutes;
          int seconds;
          double sec_dbl;
          char str_min[256];
          char per_sec[256];

          /* Transfer time in seconds */
          ssh_time_measure_stop(timer);
          ssh_time_measure_get_value(timer, &time_sec, &time_nsec);
          minutes = time_sec / 60;
          seconds = time_sec % 60;

          if (minutes > 0)
            snprintf(str_min, sizeof(str_min), "%d minute%s ", 
                     minutes,
                     (minutes != 1) ? "s" : "");
          else
            str_min[0] = '\000';

          sec_dbl = (double)ssh_time_measure_get(timer, 
                                                 SSH_TIME_GRANULARITY_SECOND);
          if (sec_dbl > 0.0)
            {
              snprintf(per_sec, sizeof(per_sec), " [%.2f kB/sec]", 
                       (((double)file_len) / (sec_dbl * 1024.0)));
            }
          else
            {
              per_sec[0] = '\000';
            }

          printf("\n%lu bytes transferred in %s%d.%02d seconds%s.\n",
                 (unsigned long)file_len,
                 str_min,
                 seconds,
                 (int)(time_nsec / 10000000),
                 per_sec);
        }
    }
  
  ssh_time_measure_free(timer);
  scp_file_close(session, src_handle);

  if (!session->do_not_copy)
    {
      if (session->preserve_flag)
        scp_file_fsetstat(session, dst_handle, src_attributes);
      scp_file_close(session, dst_handle);
    }
  return TRUE;
      
 close_error:
  if (src_handle != NULL)
    scp_file_close(session, src_handle);
  if (dst_handle != NULL)
    scp_file_close(session, dst_handle);
  return FALSE;
}

void scp_set_error(ScpSession session, int error)
{
  if (error == 0)
    session->error = 0;    
  else if (session->error == 0)
    session->error = error;
  else if (session->error != error)
    session->error = SCP_ERROR_MULTIPLE;
}

Boolean scp_is_dst_directory(ScpSession session)
{
  session->callback_fired = 0;

  ssh_file_client_stat(session->dst_client, 
                       session->dst_location->file, 
                       scp_is_dst_directory_callback,
                       session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
                       0,
                       scp_remote_dead_timeout, 
                       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);

  return (session->dst_is_dir != 0);
}

int scp_execute(ScpSession session)
{
  SshStream tmp1a, tmp1b, tmp2a, tmp2b;
  Boolean r;

  ssh_stream_pair_create(&tmp2a, &tmp2b);  
  session->src_local_server = ssh_file_server_wrap(tmp2a);
  session->src_local_client = ssh_file_client_wrap(tmp2b);

  if (session->dst_is_local)
    {
      ssh_stream_pair_create(&tmp1a, &tmp1b);  
      session->dst_local_server = ssh_file_server_wrap(tmp1a);
      session->dst_local_client = ssh_file_client_wrap(tmp1b);
      session->dst_client = session->dst_local_client;
    }
  else
    {
      if (session->dst_remote_client)
        {
          ssh_xfree(session->dst_remote_client);
          session->dst_remote_client = NULL;
        }
      
      session->dst_remote_client =
        scp_open_remote_connection(session,
                                   session->dst_location->host,
                                   session->dst_location->user,
                                   session->dst_location->port);
      if (session->dst_remote_client == NULL)
        ssh_fatal("Cannot reach the destination.");

      session->dst_client = session->dst_remote_client;
    }

  scp_abort_if_remote_dead(session, session->dst_client);
  scp_is_dst_directory(session);
  if (!session->dst_is_dir && session->need_dst_dir)
    {
      ssh_warning("Destination file is not a directory.");
      ssh_warning("Exiting.");
      exit(SCP_ERROR_USAGE);
    }

  /*scp_print_session_info(session);*/

  while (session->src_list != NULL)
    {
      scp_set_next_src_location((void *)session);

      if (!session->current_src_location)
        break;

      /* If we have been executed with '-r' option, create directories
         in the remote end.*/
      if (session->recurse_flag)
        {
          SSH_DEBUG(4, ("file = \"%s\", dir_mask = \"%s\", is_dir = %d",
                        session->current_src_location->file,
                        (session->current_src_location->dir_mask ?
                         session->current_src_location->dir_mask :
                         "NULL"),
                        session->current_src_location->is_dir));

          /* create needed directories */
          if (session->current_src_location->is_dir == 1)
            {
              if (session->preserve_flag)
                {
                  SSH_DEBUG(3, ("Preserve flag is on, but we don't have " \
                                "directory's attributes. (source dirname " \
                                "\"%s\")",
                                session->current_src_location->file));
                }
              
              SSH_DEBUG(4, ("Creating destination directory \"%s\"...",
                            session->current_dst_file));
              
              if (scp_file_mkdir(session,
                                 session->dst_client,
                                 session->current_dst_file,
                                 (session->current_src_location->dir_attrs ?
                                  session->current_src_location->dir_attrs :
                                  NULL)))
                ssh_warning("Creating destination directory \"%s\" " \
                              "failed.(status = %d)",
                              session->current_dst_file,
                              session->tmp_status);
          
              
              continue;
            }
        }

      r = scp_move_file(session,
                        session->current_src_location->host,
                        session->current_src_location->file,
                        (session->current_src_is_local ? 
                         session->src_local_client :
                         session->src_remote_client),
                        session->dst_location->host,
                        session->current_dst_file, 
                        session->dst_client);
    }

  if (session->src_remote_client != NULL)
    ssh_file_client_destroy(session->src_remote_client);
  if (session->dst_client != NULL)
    ssh_file_client_destroy(session->dst_client);

  /*scp_print_session_info(session);*/

  return session->error;
}

/* eof (scp2.c) */
