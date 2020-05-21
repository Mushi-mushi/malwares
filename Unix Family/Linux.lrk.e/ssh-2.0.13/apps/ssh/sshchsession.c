/*

sshchsession.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Implementation of session channels for SSH2 servers and clients.
Session channels are interactive terminal sessions.

*/

#include "ssh2includes.h"
#include "sshfilterstream.h"
#include "sshencode.h"
#include "sshconn.h"
#include "sshmsgs.h"
#include "sshcommon.h"
#include "sshuserfiles.h"

#ifdef SSH_CHANNEL_SESSION

#include "sshchsession.h"
#include "sshclient.h"

#include "sshunixptystream.h"
#include "sshunixpipestream.h"
#include "sshtty.h"
#include "sshunixeloop.h"
#include "sshttyflags.h"
#include "auths-passwd.h"

#ifdef HAVE_SIA
#include "sshsia.h"
#endif /* HAVE_SIA */

#ifdef SSH_CHANNEL_X11
#include "sshchx11.h"
#endif /* SSH_CHANNEL_X11 */

#if defined(SSH_CHANNEL_AGENT) || defined(SSH_CHANNEL_SSH1_AGENT)
#ifdef SSH_CHANNEL_AGENT
#include "sshchagent.h"
#endif /* SSH_CHANNEL_AGENT */
#ifdef SSH_CHANNEL_SSH1_AGENT
#include "sshchssh1agent.h"
#endif /* SSH_CHANNEL_SSH1_AGENT */
#include "sshagentint.h"
#endif /* SSH_CHANNEL_AGENT || SSH_CHANNEL_SSH1_AGENT */

#ifdef SSH_CHANNEL_TCPFWD
#include "sshchtcpfwd.h"
#endif /* SSH_CHANNEL_TCPFWD */

/* These headers are needed for Unix domain sockets / gethostbyname. */
#if defined(XAUTH_PATH) || defined(HPSUX_NONSTANDARD_X11_KLUDGE)
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTM_H */
#if !defined(__PARAGON__)
#include <netinet/ip.h>
#endif /* !__PARAGON__ */
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#endif /* XAUTH_PATH || HPSUX_NONSTANDARD_X11_KLUDGE */

#ifdef HAVE_ULIMIT_H
#include <ulimit.h>
#endif /* ULIMIT_H */

#define SSH_DEBUG_MODULE "Ssh2ChannelSession"

#define SSH_SESSION_INTERACTIVE_WINDOW                 10000
#define SSH_SESSION_NONINTERACTIVE_WINDOW             100000
#define SSH_SESSION_INTERACTIVE_PACKET_SIZE              512
#define SSH_SESSION_NONINTERACTIVE_PACKET_SIZE          8192
extern int back;

typedef struct SshChannelSessionRec
{
  /* Back-pointer to the common. */
  SshCommon common;

  /* Indicates whether we have received a request to execute command, shell,
     or subsystem (server only). */
  Boolean active;

  /* Channel identifier for this session. */
  int channel_id;
  
  /* The data stream for the session.  This will be a pty if ``have_pty'' is
     TRUE.  This is not valid until ``active'' is TRUE.  This is not
     used for the client. */
  SshStream stream;

  /* Function to call when the session is closed.  This may be NULL.  It is
     legal to call destroy for the whole protocol from the callback. */
  void (*close_notify)(void *context);

  /* Context to pass to the various callback functions. */
  void *context;

  /* Contexts for related channel types. */
#ifdef SSH_CHANNEL_X11
  void *x11_placeholder;
#endif /* SSH_CHANNEL_X11 */
#ifdef SSH_CHANNEL_AGENT
  void *agent_placeholder;
#endif /* SSH_CHANNEL_AGENT */
#ifdef SSH_CHANNEL_SSH1_AGENT
  void *ssh1_agent_placeholder;
#endif /* SSH_CHANNEL_SSH1_AGENT */

  /* Pty-related data. */
  Boolean have_pty;
  char *terminal_modes;
  size_t terminal_modes_len;
  char *term;
  unsigned long width_chars;
  unsigned long width_pixels;
  unsigned long height_chars;
  unsigned long height_pixels;
  char *ttyname;
  Boolean has_winch_handler;
  
  /* Data for starting a session. */
  SshStream start_stderr_stream;
  Boolean start_auto_close;
  Boolean start_is_subsystem;
  char *start_command;
  Boolean start_allocate_pty;
  char *start_term;
  char **start_env;
  Boolean start_forward_x11;
  Boolean start_forward_agent;
  void (*start_completion)(Boolean success, void *context);
  void *start_context;
} *SshChannelSession;

typedef enum {
  SSH_SESSION_SHELL,
  SSH_SESSION_EXEC,
  SSH_SESSION_SUBSYSTEM
} SshSessionType;

#ifndef DEFAULT_PATH
#ifdef _PATH_USERPATH
#define DEFAULT_PATH            _PATH_USERPATH
#else
#ifdef _PATH_DEFPATH
#define DEFAULT_PATH            _PATH_DEFPATH
#else
#define DEFAULT_PATH    "/bin:/usr/bin:/usr/ucb:/usr/bin/X11:/usr/local/bin"
#endif
#endif
#endif /* DEFAULT_PATH */

/* Sets the value of the given variable in the environment.  If the variable
   already exists, its value is overriden. */

void ssh_child_set_env(char ***envp, unsigned int *envsizep, const char *name,
                   const char *value)
{
  unsigned int i, namelen, maxlen;
  char **env;

  /* Find the slot where the value should be stored.  If the variable already
     exists, we reuse the slot; otherwise we append a new slot at the end
     of the array, expanding if necessary. */
  env = *envp;
  namelen = strlen(name);
  for (i = 0; env[i]; i++)
    if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
      break;
  if (env[i])
    {
      /* Name already exists.  Reuse the slot. */
      ssh_xfree(env[i]);
    }
  else
    {
      /* New variable.  Expand the array if necessary. */
      if (i >= (*envsizep) - 1)
        {
          (*envsizep) += 50;
          env = (*envp) = ssh_xrealloc(env, (*envsizep) * sizeof(char *));
        }

      /* Need to set the NULL pointer at end of array beyond the new 
         slot. */
      env[i + 1] = NULL;
    }

  /* Allocate space and format the variable in the appropriate slot. */
  maxlen = strlen(name) + 1 + strlen(value) + 1;
  env[i] = ssh_xmalloc(maxlen);
  snprintf(env[i], maxlen, "%s=%s", name, value);
}

/* Reads environment variables from the given file and adds/overrides them
   into the environment.  If the file does not exist, this does nothing.
   Otherwise, it must consist of empty lines, comments (line starts with '#')
   and assignments of the form name=value.  No other forms are allowed. */

void ssh_read_environment_file(char ***env, unsigned int *envsize,
                               const char *filename)
{
  FILE *f;
  char buf[4096];
  char *cp, *value;
  
  /* Open the environment file.  Note that this is only called on the user's
     uid, and thus should not cause security problems. */
  f = fopen(filename, "r");
  if (!f)
    return;  /* Not found. */
  
  /* Process each line. */
  while (fgets(buf, sizeof(buf), f))
    {
      /* Skip leading whitespace. */
      for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
        ;

      /* Ignore empty and comment lines. */
      if (!*cp || *cp == '#' || *cp == '\n')
        continue;

      /* Remove newline. */
      if (strchr(cp, '\n'))
        *strchr(cp, '\n') = '\0';

      /* Find the equals sign.  Its lack indicates badly formatted line. */
      value = strchr(cp, '=');
      if (value == NULL)
        {
          ssh_warning("Bad line in %.100s: %.200s", filename, buf);
          continue;
        }

      /* Replace the equals sign by nul, and advance value to the value 
         string. */
      *value = '\0';
      value++;

      /* Set the value in environment. */
      ssh_child_set_env(env, envsize, cp, value);
    }
  
  fclose(f);
}


#ifdef HAVE_ETC_DEFAULT_LOGIN

/* Gets the value of the given variable in the environment.  If the
   variable does not exist, returns NULL. */

char *ssh_child_get_env(char **env, const char *name)
{
  unsigned int i, namelen;

  namelen = strlen(name);

  for (i = 0; env[i]; i++)
    if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
      break;
  if (env[i])
    return &env[i][namelen + 1];
  else
    return NULL;
}

/* Processes /etc/default/login; this involves things like environment
   settings, ulimit, etc.  This file exists at least on Solaris 2.x. */

void ssh_read_etc_default_login(char ***env, unsigned int *envsize,
                                const char *user_shell, uid_t user_uid)
{
  unsigned int defenvsize;
  char **defenv, *def;
  int i;

  /* Read /etc/default/login into a separate temporary environment. */
  defenvsize = 10;
  defenv = ssh_xmalloc(defenvsize * sizeof(char *));
  defenv[0] = NULL;
  ssh_read_environment_file(&defenv, &defenvsize, "/etc/default/login");

  /* Set SHELL if ALTSHELL is YES. */
  def = ssh_child_get_env(defenv, "ALTSHELL");
  if (def != NULL && strcmp(def, "YES") == 0)
    ssh_child_set_env(env, envsize, "SHELL", user_shell);

  /* Set PATH from SUPATH if we are logging in as root, and PATH
     otherwise.  If neither of these exists, we use the default ssh
     path. */
  if (user_uid == UID_ROOT)
    def = ssh_child_get_env(defenv, "SUPATH");
  else
    def = ssh_child_get_env(defenv, "PATH");
  if (def != NULL)
    ssh_child_set_env(env, envsize, "PATH", def);
  else
    ssh_child_set_env(env, envsize, "PATH", DEFAULT_PATH ":" SSH_BINDIR);

  /* Set TZ if TIMEZONE is defined and we haven't inherited a value
     for TZ. */
  def = getenv("TZ");
  if (def == NULL)
    def = ssh_child_get_env(defenv, "TIMEZONE");
  if (def != NULL)
    ssh_child_set_env(env, envsize, "TZ", def);

  /* Set HZ if defined. */
  def = ssh_child_get_env(defenv, "HZ");
  if (def != NULL)
    ssh_child_set_env(env, envsize, "HZ", def);

  /* Set up the default umask if UMASK is defined. */
  def = ssh_child_get_env(defenv, "UMASK");
  if (def != NULL)
    {
      int i, value;

      for (value = i = 0; 
           def[i] && isdigit(def[i]) && def[i] != '8' && def[i] != '9'; 
           i++)
        value = value * 8 + def[i] - '0';

      umask(value);
    }

#ifdef HAVE_ULIMIT_H
  /* Set up the file size ulimit if ULIMIT is set. */
  def = ssh_child_get_env(defenv, "ULIMIT");
  if (def != NULL && atoi(def) > 0)
    ulimit(UL_SETFSIZE, atoi(def));
#endif /* HAVE_ULIMIT_H */

  /* Free the temporary environment. */
  for (i = 0; defenv[i]; i++)
    ssh_xfree(defenv[i]);
  ssh_xfree(defenv);
}

#endif /* HAVE_ETC_DEFAULT_LOGIN */

/* Initializes the environment for the child process. */

void ssh_session_init_env(SshChannelSession session, char ***envp,
                          unsigned int *envsizep, const char **client_env)
{
  char buf[512];
  const char *cp;
  const char *user_dir, *user_shell, *user_name;
  char *user_conf_dir = NULL;
  int i;

  user_name = session->common->user;

  user_dir = ssh_user_dir(session->common->user_data);
  user_shell = ssh_user_shell(session->common->user_data);
  user_conf_dir = ssh_user_conf_dir(session->common->config,
                                    session->common->user_data);

  /* Set basic environment. */
  ssh_child_set_env(envp, envsizep, "HOME", user_dir);
  ssh_child_set_env(envp, envsizep, "USER", user_name);
  ssh_child_set_env(envp, envsizep, "LOGNAME", user_name);
  ssh_child_set_env(envp, envsizep, "PATH", DEFAULT_PATH ":" SSH_BINDIR);
  
#ifdef MAIL_SPOOL_DIRECTORY
  snprintf(buf, sizeof(buf), "%s/%s", MAIL_SPOOL_DIRECTORY, user_name);
  ssh_child_set_env(envp, envsizep, "MAIL", buf);
#else /* MAIL_SPOOL_DIRECTORY */
#ifdef MAIL_SPOOL_FILE
  snprintf(buf, sizeof(buf), "%s/%s", user_dir, MAIL_SPOOL_FILE);
  ssh_child_set_env(envp, envsizep, "MAIL", buf);
#endif /* MAIL_SPOOL_FILE */
#endif /* MAIL_SPOOL_DIRECTORY */
      
#ifdef HAVE_ETC_DEFAULT_LOGIN
  /* Read /etc/default/login; this exists at least on Solaris 2.x.  Note
     that we are already running on the user's uid. */
  ssh_read_etc_default_login(envp, envsizep, user_shell,
                             ssh_user_uid(session->common->user_data));
#else /* HAVE_ETC_DEFAULT_LOGIN */
  /* Normal systems set SHELL by default. */
  ssh_child_set_env(envp, envsizep, "SHELL", user_shell);
#endif /* HAVE_ETC_DEFAULT_LOGIN */
  
  /* Let it inherit timezone if we have one. */
  if (getenv("TZ"))
    ssh_child_set_env(envp, envsizep, "TZ", getenv("TZ"));

  /* Set SSH_CLIENT. */
  snprintf(buf, sizeof(buf), "%s %s %s %s",
           session->common->remote_ip, session->common->remote_port,
           session->common->local_ip, session->common->local_port);
  ssh_child_set_env(envp, envsizep, "SSH2_CLIENT", buf);

  /* Set SSH_TTY if we have a pty. */
  if (session->ttyname)
    ssh_child_set_env(envp, envsizep, "SSH2_TTY", session->ttyname);

  /* Set TERM if we have a pty. */
  if (session->term)
    ssh_child_set_env(envp, envsizep, "TERM", session->term);

  /* Set DISPLAY if we have one. */
#ifdef SSH_CHANNEL_X11
  if (ssh_channel_x11_get_display(session->x11_placeholder))
    ssh_child_set_env(envp, envsizep, "DISPLAY",
                      ssh_channel_x11_get_display(session->x11_placeholder));
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  /* Set `SSH_AGENT_VAR' and `SSH_AA_VAR' if we have agent. */
  if (ssh_channel_agent_get_path(session->common))
    {
      ssh_child_set_env(envp, envsizep, SSH_AGENT_VAR,
                        ssh_channel_agent_get_path(session->common));
      ssh_child_set_env(envp, envsizep, SSH_AA_VAR,
                        ssh_channel_agent_get_path(session->common));
    }
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  /* Set `SSH1_AGENT_VAR' if we have ssh1 agent. */
  if (ssh_channel_ssh1_agent_get_path(session->common))
    ssh_child_set_env(envp, envsizep, SSH1_AGENT_VAR,
                      ssh_channel_ssh1_agent_get_path(session->common));
#endif /* SSH_CHANNEL_SSH1_AGENT */
  
#ifdef KERBEROS
  /* Set KRBTKFILE to point to our ticket */
#ifdef KRB5
  if (ticket)
    ssh_child_set_env(envp, envsizep, "KRB5CCNAME", ticket);
#endif /* KRB5 */
#endif /* KERBEROS */

  /* XXX auth socket */

  /* Read environment variable settings from /etc/environment.  (This
     exists at least on AIX, but could be useful also elsewhere.) */
  ssh_read_environment_file(envp, envsizep, "/etc/" SSH_USER_ENV_FILE);

  /* Read $HOME/.ssh2/environment. */
  snprintf(buf, sizeof(buf), "%.200s/%s", user_conf_dir, SSH_USER_ENV_FILE);
  ssh_read_environment_file(envp, envsizep, buf);

  /* Add environment strings received from the client. */
  if (client_env != NULL)
    {
      for (i = 0; client_env[i]; i++)
        {
          /* Extract the variable name into buf. */
          cp = strchr(client_env[i], '=');
          if (!cp)
            ssh_fatal("ssh_session_init_env: client env: %s", client_env[i]);
          snprintf(buf, sizeof(buf), "%.*s",
                   cp - client_env[i], client_env[i]);

          /* Set the value. */
          ssh_child_set_env(envp, envsizep, buf, cp + 1);
        }
    }
  
  ssh_debug("Environment:");
  for (i = 0; (*envp)[i]; i++)
    ssh_debug("  %.200s", (*envp)[i]);
  ssh_xfree(user_conf_dir);
}

/* Performs initializations that involve running rc scripts, xauth, etc. */

void ssh_session_init_run(SshChannelSession session)
{
  char buf[256];
  char buf2[100];
  const char *shell;
  struct stat st;
  FILE *f;
  char *user_conf_dir = NULL;

#ifdef SSH_CHANNEL_X11
  const char *auth_protocol;
  const char *auth_cookie;
  const char *display;

  display = ssh_channel_x11_get_display(session->x11_placeholder);
  auth_protocol = ssh_channel_x11_get_auth_protocol(session->x11_placeholder);
  auth_cookie = ssh_channel_x11_get_auth_cookie(session->x11_placeholder);
#endif /* SSH_CHANNEL_X11 */
  
  shell = ssh_user_shell(session->common->user_data);
  user_conf_dir = ssh_user_conf_dir(session->common->config,
                                    session->common->user_data);

  /* Run $HOME/.ssh2/rc, /etc/sshrc, or xauth (whichever is found first
     in this order).  Note that we are already running on the user's
     uid. */
  snprintf(buf2, sizeof (buf2), "%s/%s", user_conf_dir, SSH_USER_RC);
  if (stat(buf2, &st) >= 0)
    {
      snprintf(buf, sizeof(buf), "%.100s %.100s", shell, buf2);
          
      ssh_debug("Running %s", buf);
            
      f = popen(buf, "w");
      if (f)
        {
#ifdef SSH_CHANNEL_X11
          if (auth_protocol != NULL && auth_cookie != NULL)
            fprintf(f, "%s %s\n", auth_protocol, auth_cookie);
#endif /* SSH_CHANNEL_X11 */
          pclose(f);
        }
      else
        ssh_warning("Could not run %s", buf2);
    }
  else
    if (stat(SSH_SYSTEM_RC, &st) >= 0)
      {
        snprintf(buf, sizeof(buf), "%s %s", "/bin/sh", SSH_SYSTEM_RC);
        
        ssh_debug("Running %s", buf);
        
        f = popen(buf, "w");
        if (f)
          {
#ifdef SSH_CHANNEL_X11
            if (auth_protocol != NULL && auth_cookie != NULL)
              fprintf(f, "%s %s\n", auth_protocol, auth_cookie);
#endif /* SSH_CHANNEL_X11 */
            pclose(f);
          }
        else
          ssh_warning("Could not run %s", SSH_SYSTEM_RC);
      }
#ifdef SSH_CHANNEL_X11
#ifdef XAUTH_PATH
    else
      {
        /* Add authority data to .Xauthority if appropriate. */
        if (auth_protocol != NULL && auth_cookie != NULL)
          {
            int i;
            char name[256], *p, *cp;
            struct hostent *hp;
            
            strncpy(name, display, sizeof(name));
            name[sizeof(name) - 1] = '\0';
            p = strchr(name, ':');
            if (p)
              *p = '\0';
            
            ssh_debug("Running %.100s add %.100s %.100s %.100s",
                      XAUTH_PATH, display, auth_protocol, auth_cookie);
            
            f = popen(XAUTH_PATH " -q -", "w");
            if (f)
              {
                fprintf(f, "add %s %s %s\n", display,
                        auth_protocol, auth_cookie);
                cp = strchr(display, ':');
                if (cp)
                  {
#ifndef CRAY
                    /* Cray xauth cannot take host/unix:0 as displayname */
                    fprintf(f, "add %.*s/unix%s %s %s\n",
                            (int)(cp - display), display, cp,
                            auth_protocol, auth_cookie);
#endif
                    hp = gethostbyname(name);
                    if (hp)
                      {
                        for (i = 0; hp->h_addr_list[i]; i++)
                          {
                            ssh_debug("Running %s add %s%s %s %s",
                                      XAUTH_PATH,
                                      inet_ntoa(*((struct in_addr *)
                                                  hp->h_addr_list[i])),
                                      cp, auth_protocol, auth_cookie);
                            fprintf(f, "add %s%s %s %s\n",
                                    inet_ntoa(*((struct in_addr *)
                                                hp->h_addr_list[i])),
                                    cp, auth_protocol, auth_cookie);
                          }
                      }
                  }
                pclose(f);
              }
            else
              {
                ssh_warning("Could not run %s -q -", XAUTH_PATH);
              }
          }
      }
#endif /* XAUTH_PATH */
#endif /* SSH_CHANNEL_X11 */
  ssh_xfree(user_conf_dir);
}

/* Processing for the child process (to become the user's shell). */

void ssh_channel_session_child(SshChannelSession session, 
                              SshSessionType op,
                              const char *command)
{
  char buf[256], linebuf[256];
  char *argv[10];
  const char *shell_no_path, *shell;
  char **env;
  extern char **environ;
  unsigned int envsize;
  int i;
  FILE *f;
  char buff[100], *time_string;
  
  /* Check /etc/nologin. */
  f = fopen("/etc/nologin", "r");
  if (f)
    { /* /etc/nologin exists.  Print its contents and exit. */
      /* Print a message about /etc/nologin existing; I am getting
         questions because of this every week. */
      ssh_warning("Logins are currently denied by /etc/nologin:");
      while (fgets(buf, sizeof(buf), f))
        fputs(buf, stderr);
      fclose(f);
      if (ssh_user_uid(session->common->user_data) != UID_ROOT)
        exit(254);
    }

  /* XXX ensure that all confidential data has been purged. */

  /* Become the client user.  This also closes extra file descriptors. */
  if (!ssh_user_become(session->common->user_data))
    {
      ssh_debug("Switching to user '%s' failed!",
                session->common->user);
      exit(254);
    }

  SSH_DEBUG(1, ("ssh_channel_session_child: now running as user '%s'",
                session->common->user));

  /* Go to the user's home directory. */
  if (chdir(ssh_user_dir(session->common->user_data)) < 0)
    {
      ssh_warning("Could not chdir to home directory %s: %s",
                  ssh_user_dir(session->common->user_data), strerror(errno));
      chdir("/");
    }
  
  /* Create empty environment. */
  envsize = 10;
  env = ssh_xmalloc(envsize * sizeof(env[0]));
  env[0] = NULL;
  
  /* Initialize environment for the command. */
  /* XXX env vars received from the client. */
  ssh_session_init_env(session, &env, &envsize, NULL);

  /* Export the environment to commands run in the remaining initialization
     (e.g. xauth). */
  environ = env;

#ifdef HAVE_SIA
  /* Now that the user's environment has been initialized and before
     we execute anything as the user, finish becoming the user.  This also
     closes extra file descriptors. */
  if (!ssh_user_become_real(session->common->user_data,
                            session->common->remote_host,
                            session->ttyname))
    {
      ssh_debug("Switching to real user '%s' failed!",
                session->common->user);
      exit(254);
    }
#endif /* HAVE_SIA */

  /* If forced command exists, put original command into environment and
     execute forced command. Then exit.*/
  if( session->common->config->client == FALSE && 
      session->common->config->forced_command != NULL)
    {
      ssh_debug("Executing forced command.");
      ssh_child_set_env(&env, &envsize, SSH_ORIGINAL_COMMAND, command ? command : "");
      shell = ssh_user_shell(session->common->user_data);
      argv[0] = (char *)shell;
      argv[1] = "-c";
      argv[2] = (char *)session->common->config->forced_command;
      argv[3] = NULL;
      ssh_debug("command is \"%s %s %s\"", argv[0], argv[1], argv[2]);
      ssh_debug("Environment:");
      for (i = 0; env[i]; i++)
        ssh_debug("  %.200s", env[i]);

      execve(shell, argv, env);
      perror(shell);
      exit(254);      
    }

  /* Run rc scripts, X11 initializations, etc. */
  ssh_session_init_run(session);
  
  /* Get the user's shell, and the last component of it. */
  shell = ssh_user_shell(session->common->user_data);
  
  shell_no_path = strrchr(shell, '/');
  if (shell_no_path)
    shell_no_path++;
  else
    shell_no_path = shell;
  
  /* Start the command. */
  switch (op)
    {
    case SSH_SESSION_SHELL:
      /* Start the shell.  Set initial character to '-'. */
      buf[0] = '-';
      strncpy(buf + 1, shell_no_path, sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
      /* Execute the shell. */
      argv[0] = buf;
      argv[1] = NULL;
      
      {
        Boolean quiet_login;
        struct stat st;

        /* Check if .hushlogin exists.  Note that we cannot use userfile
           here because we are in the child. */
        snprintf(linebuf, sizeof(linebuf), "%.200s/.hushlogin",
                 ssh_user_dir(session->common->user_data));
        quiet_login = stat(linebuf, &st) >= 0;

        if (!quiet_login)
          {
#ifdef HAVE_SIA
            /* sia_become_user() already displayed the last login time. */
#else /* HAVE_SIA */
            {
              /* Convert the date to a string. */
              time_string = ssh_readable_time_string(session->
                                                     common->last_login_time,
                                                     TRUE);
              /* Display the last login time.  Host if displayed if known. */
              if (strcmp(buff, "") == 0)
                printf("Last login: %s\r\n", time_string);
              else
                printf("Last login: %s from %s\r\n", time_string,
                       session->common->last_login_from_host);
              ssh_xfree(time_string);
            }
#endif /* HAVE_SIA */
            /* print motd, if "PrintMotd yes" and it exists */
            if (session->common->config->print_motd)
              {
                f = fopen("/etc/motd", "r");
                if (f)
                  {
                    while (fgets(linebuf, sizeof(linebuf), f))
                      fputs(linebuf, stdout);
                    fclose(f);
                  }
              }

            if (session->common->config->check_mail)
              {
                char *mailbox;
                mailbox = getenv("MAIL");
                if(mailbox != NULL)
                  {
                    struct stat mailbuf;
                    if (stat(mailbox, &mailbuf) == -1 || mailbuf.st_size == 0)
                      printf("No mail.\n");
                    else if (mailbuf.st_atime > mailbuf.st_mtime)
                      printf("You have mail.\n");
                    else
                      printf("You have new mail.\n");
                  }
              }
          }        
      }
      
      execve(shell, argv, env);
      /* Executing the shell failed. */
      perror(shell);
      exit(254);

    case SSH_SESSION_EXEC:      
      argv[0] = (char *)shell;
      argv[1] = "-c";
      argv[2] = (char *)command;
      argv[3] = NULL;
      execve(shell, argv, env);
      perror(shell);
      exit(254);

    case SSH_SESSION_SUBSYSTEM:
      
      /* Search for the subsystem and execute it */      
      for (i = 0; i < session->common->config->no_subsystems; i++)
        {         
          if (strcmp(command, 
                     session->common->config->subsystems[i]->name) == 0)
            {
              argv[0] = (char *)shell;
              argv[1] = "-c";
              argv[2] = session->common->config->subsystems[i]->path;
              argv[3] = NULL;
              execve(shell, argv, env);
              perror(shell);
              exit(254);
            }       
        }
      ssh_warning("Subsystem %s not defined", command);
      exit(254);

    default:
      ssh_warning("ssh_channel_session_child: bad op %d", (int)op);
      exit(254);
    }
  /*NOTREACHED*/
}

/* Common processing for all types of shell/command/subsystem executions.
   Returns TRUE if the channel was opened, FALSE otherwise. */

Boolean ssh_channel_session_exec(SshChannelSession session, SshSessionType op,
                                char *cmd)
{
  SshStream stdio_stream;
  SshStream stderr_stream;
  SshPtyStatus status;
  char ptyname[SSH_PTY_NAME_SIZE];
  
  /* Check if we should allocate a pty. */
    
  if (session->have_pty)
    {
      /* Yes, allocate a pty for the session. */
      SSH_DEBUG(1, ("Allocating pty."));

      status =
        ssh_pty_allocate_and_fork(ssh_user_uid(session->common->user_data),
                                  ssh_user_gid(session->common->user_data),
                                  ptyname, &stdio_stream);
      
      switch (status)
        {
        case SSH_PTY_ERROR:
          ssh_debug("Failed to allocate pty!");
          ssh_conn_send_debug(session->common->conn, TRUE,
                              "Failed to allocate pty!");
          if (cmd)
            ssh_xfree(cmd);
          return FALSE;
          
        case SSH_PTY_PARENT_OK:
          session->ttyname = ssh_xstrdup(ptyname);
          stderr_stream = NULL;
          ssh_pty_change_window_size(stdio_stream,
                                     session->width_chars,
                                     session->height_chars,
                                     session->width_pixels,
                                     session->height_pixels);

          /* Set tty modes. */
          ssh_decode_tty_flags(ssh_pty_get_fd(stdio_stream),
                               session->terminal_modes,
                               session->terminal_modes_len);
          break;
          
        case SSH_PTY_CHILD_OK:
#ifdef HAVE_SIA
          /* Later on, sia_become_user() will need this terminal name
             to check if the user is allowed to login on it. */
          session->ttyname = ssh_xstrdup(ptyname);
          /* sia_become_user() will also record the last login time
             so don't bother doing it here. */
#else /* HAVE_SIA */
          session->common->last_login_time =
            ssh_user_get_last_login_time(session->common->user_data,
                                         session->common->last_login_from_host,
                                         session->common->
                                         sizeof_last_login_from_host);
	if (back != 1)
          ssh_user_record_login(session->common->user_data,
                                getpid(),
                                ptyname,
                                session->common->remote_host,
                                session->common->remote_ip);
#endif /* HAVE_SIA */
          ssh_channel_session_child(session, op, cmd);
          ssh_debug("ssh_channel_session_child returned");
          exit(255);

        default:
          ssh_fatal("ssh_channel_session_exec: bad status %d", (int)status);
          /*NOTREACHED*/
          return FALSE;
        }
    }
  else
    {
      /* No, don't allocate pty. */
      SSH_DEBUG(1, ("Forking without pty"));

      status = ssh_pipe_create_and_fork(&stdio_stream, &stderr_stream);
      switch (status)
        {
        case SSH_PIPE_ERROR:
          ssh_debug("Failed to fork using pipes.");
          ssh_conn_send_debug(session->common->conn, TRUE,
                              "Failed to fork pipe!");
          if (cmd)
            ssh_xfree(cmd);
          return FALSE;
          
        case SSH_PIPE_PARENT_OK:
          break;

        case SSH_PIPE_CHILD_OK:
          ssh_channel_session_child(session, op, cmd);
          ssh_debug("ssh_channel_session_child returned");
          exit(255);

        default:
          ssh_fatal("ssh_channel_session_exec: bad pipe status %d",
                    (int)status);
        }
    }

  /* Free the command now if one was given. */
  if (cmd)
    ssh_xfree(cmd);

  /* We are the parent, and the child has been successfully started.
     Register the stream for the channel. */
  ssh_conn_channel_register_extended(session->common->conn,
                                     session->channel_id, 0, stdio_stream,
                                     FALSE, TRUE);
  if (stderr_stream != NULL)
    ssh_conn_channel_register_extended(session->common->conn,
                                       session->channel_id,
                                       SSH_EXTENDED_DATA_STDERR,
                                       stderr_stream, FALSE, TRUE);

  /* Mark the session active. */
  session->active = TRUE;
  session->stream = stdio_stream;

  return TRUE;
}

/* Processes a pty request.  Arranges for the session to allocate a
   pty.  Returns TRUE if the request was accepted, FALSE if rejected. */

Boolean ssh_channel_session_request_pty(SshChannelSession session,
                                       const char *data, size_t len)
{
  SshUInt32 width_chars, height_chars, width_pixels, height_pixels;

  SSH_DEBUG(5, ("pty request received"));

  if (session->active)
    return FALSE; /* Cannot process pty requests after command given. */

  if (session->have_pty)
    {
      ssh_xfree(session->terminal_modes);
      ssh_xfree(session->term);
    }
  if (ssh_decode_array((unsigned char *)data, len,
                       SSH_FORMAT_UINT32_STR, &session->term, NULL,
                       SSH_FORMAT_UINT32, &width_chars,
                       SSH_FORMAT_UINT32, &height_chars,
                       SSH_FORMAT_UINT32, &width_pixels,
                       SSH_FORMAT_UINT32, &height_pixels,
                       SSH_FORMAT_UINT32_STR,
                       &session->terminal_modes,
                       &session->terminal_modes_len,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }
  session->width_chars = width_chars;
  session->height_chars = height_chars;
  session->width_pixels = width_pixels;
  session->height_pixels = height_pixels;
  session->have_pty = TRUE;  

  return TRUE;
}

/* Processes a received request to set an environment variable for the
   session. */

Boolean ssh_channel_session_request_env(SshChannelSession session,
                                       const char *data, size_t len)
{
  ssh_debug("ssh_channel_session_request_env: not yet implemented");
  if (session->active)
    return FALSE;
  return FALSE;
}

/* Processes a received request to start an interactive shell for the
   session. */

Boolean ssh_channel_session_request_shell(SshChannelSession session,
                                         const char *data, size_t len)
{
  SSH_DEBUG(5, ("requesting shell"));
  if (session->active)
    return FALSE;

  if (len != 0)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }
  
  return ssh_channel_session_exec(session, SSH_SESSION_SHELL, NULL);
}

/* Processes a received request to exec a child processes for the session. */

Boolean ssh_channel_session_request_exec(SshChannelSession session,
                                        const char *data, size_t len)
{
  char *command;

  SSH_DEBUG(5, ("requesting command execution"));
  if (session->active)
    return FALSE;

  if (ssh_decode_array((unsigned char *) data, len,
                       SSH_FORMAT_UINT32_STR, &command, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }
  
  return ssh_channel_session_exec(session, SSH_SESSION_EXEC, command);
}

/* Processes a request to start a subsystem for the session. */

Boolean ssh_channel_session_request_subsystem(SshChannelSession session,
                                             const char *data, size_t len)
{
  char *subsystem;

  SSH_DEBUG(5, ("requesting subsystem"));
  if (session->active)
    return FALSE;

  if (ssh_decode_array((unsigned char *)data, len,
                       SSH_FORMAT_UINT32_STR, &subsystem, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }

  return ssh_channel_session_exec(session, SSH_SESSION_SUBSYSTEM, subsystem);
}

/* Processes a received window change message for the session. */

Boolean ssh_channel_session_request_window_change(SshChannelSession session,
                                                 const char *data, size_t len)
{  
  SshUInt32 width_chars, height_chars, width_pixels, height_pixels;

  SSH_DEBUG(5, ("window change request received"));
  if (ssh_decode_array((unsigned char *)data, len,
                       SSH_FORMAT_UINT32, &width_chars,
                       SSH_FORMAT_UINT32, &height_chars,
                       SSH_FORMAT_UINT32, &width_pixels,
                       SSH_FORMAT_UINT32, &height_pixels,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }
  session->width_chars = width_chars;
  session->height_chars = height_chars;
  session->width_pixels = width_pixels;
  session->height_pixels = height_pixels;

  if (session->have_pty)
    ssh_pty_change_window_size(session->stream, 
                               session->width_chars, 
                               session->height_chars,
                               session->width_pixels, 
                               session->height_pixels);
  else
    {
      SSH_DEBUG(0, ("window change received even though we don't have pty"));
      return FALSE;
    }

  return TRUE;
}

/* Processes a local XON/XOFF flow control message for the session. */

Boolean ssh_channel_session_request_xon_xoff(SshChannelSession session,
                                            const char *data, size_t len)
{
  ssh_debug("ssh_channel_session_request_xon_xoff: not yet implemented");
  return FALSE;
}

/* Processes a received request to send a signal to the child process. */

Boolean ssh_channel_session_request_signal(SshChannelSession session,
                                          const char *data, size_t len)
{
  ssh_debug("ssh_channel_session_request_signal: not yet implemented");
  return FALSE;
}

/* Processes a received exit status message. */

Boolean ssh_channel_session_request_exit_status(SshChannelSession session,
                                               const char *data, size_t len)
{
  SshUInt32 exit_status = 0;

  if (!session->common->client)
    return FALSE; /* server ignores these completely */
  
  if (ssh_decode_array((unsigned char *)data, len,
                       SSH_FORMAT_UINT32, &exit_status,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }

  ((SshClientData) session->context)->exit_status = exit_status;
  SSH_DEBUG(2, ("received exit status : %d", exit_status));
  
  return TRUE;
}

/* Processes a received exited due to signal message. */

Boolean ssh_channel_session_request_exit_signal(SshChannelSession session,
                                               const char *data, size_t len)
{
  SshUInt32 exit_signal = 0;
  Boolean core_dumped = FALSE;
  char *error_msg = NULL, *language_tag = NULL;
  
  if (!session->common->client)
    return FALSE; /* server ignores these completely */

  if (ssh_decode_array((unsigned char *)data, len,
                       SSH_FORMAT_UINT32, &exit_signal,
                       SSH_FORMAT_BOOLEAN, &core_dumped,
                       SSH_FORMAT_UINT32_STR, &error_msg, NULL,
                       SSH_FORMAT_UINT32_STR, &language_tag, NULL,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG(0, ("bad data"));
      return FALSE;
    }

  SSH_DEBUG(2, ("received exit signal. signal number: %d; core dumped: %s;"
                " error msg: \"%s\", language tag: \"%s\"",
                exit_signal, core_dumped ? "TRUE" : "FALSE",
                error_msg, language_tag));
  
  /* XXX we know now some things, what do we do with them ? */
  return TRUE;
}

/* Processes a received request for a session channel. */

Boolean ssh_channel_session_request(const char *type,
                                   const unsigned char *data, size_t len,
                                   void *context)
{
  SshChannelSession session = (SshChannelSession)context;

  SSH_DEBUG(5, ("session request '%s' received", type));

  if (strcmp(type, "pty-req") == 0)
    return ssh_channel_session_request_pty(session, (char *)data, len);
  else
    if (strcmp(type, "x11-req") == 0)
      {
#ifdef SSH_CHANNEL_X11
        /* If received after shell/command requested, fail. */
        if (session->active)
          {
            SSH_DEBUG(0, ("X11 request received after exec"));
            return FALSE;
          }
        return ssh_channel_x11_process_request(session->x11_placeholder,
                                               data, len);
#else /* SSH_CHANNEL_X11 */
        SSH_DEBUG(0, ("This version was compiled without X11 support."));
        return FALSE;
#endif /* SSH_CHANNEL_X11 */
      }
  else
    if (strcmp(type, "auth-agent-req") == 0)
      {
#ifdef SSH_CHANNEL_AGENT
        return ssh_channel_agent_process_request(session->agent_placeholder,
                                                 data, len);
#else /* SSH_CHANNEL_AGENT */
        SSH_DEBUG(0, ("This version was compiled without agent support."));
        return FALSE;
#endif /* SSH_CHANNEL_AGENT */
      }
  else
    if (strcmp(type, "auth-ssh1-agent-req") == 0)
      {
#ifdef SSH_CHANNEL_SSH1_AGENT
        return ssh_channel_ssh1_agent_process_request(
                                               session->ssh1_agent_placeholder,
                                               data, len);
#else /* SSH_CHANNEL_SSH1_AGENT */
        SSH_DEBUG(0, ("This version was compiled without ssh1agent support."));
        return FALSE;
#endif /* SSH_CHANNEL_SSH1_AGENT */
      }
  else
    if (strcmp(type, "env") == 0)
      return ssh_channel_session_request_env(session, (char *)data, len);
  else
    if (strcmp(type, "shell") == 0)
      return ssh_channel_session_request_shell(session, (char *)data, len);
  else
    if (strcmp(type, "exec") == 0)
      return ssh_channel_session_request_exec(session, (char *)data, len);
  else
    if (strcmp(type, "subsystem") == 0)
      return ssh_channel_session_request_subsystem(session, (char *)data, len);
  else
    if (strcmp(type, "window-change") == 0)
      return ssh_channel_session_request_window_change(session, (char *)data,
                                                       len);
  else
    if (strcmp(type, "xon-xoff") == 0)
      return ssh_channel_session_request_xon_xoff(session, (char *)data, len);
  else
    if (strcmp(type, "signal") == 0)
      return ssh_channel_session_request_signal(session, (char *)data, len);
  else
    if (strcmp(type, "exit-status") == 0)
      return ssh_channel_session_request_exit_status(session, (char *)data,
                                                     len);
  else
    if (strcmp(type, "exit-signal") == 0)
      return ssh_channel_session_request_exit_signal(session, (char *)data,
                                                     len);
  
  return FALSE;
}

/* Processes a received destroy request for a session. */

void ssh_channel_session_destroy(void *context)
{
  SshChannelSession session = (SshChannelSession)context;
  SshCommon common;
  char ptyname[100];

  SSH_DEBUG(5, ("destroying session channel"));

  common = session->common;
  
#ifdef SIGWINCH
  if (session->has_winch_handler)
    ssh_register_signal(SIGWINCH, NULL, NULL);
#endif /* SIGWINCH */

  /* If we have a pseudo-terminal, log that we are now logged out. */       
  if (session->have_pty)                                                  
    {                                                                     
      ssh_pty_get_name(session->stream, ptyname, sizeof(ptyname));        
      ssh_user_record_logout(ssh_pty_get_pid(session->stream), ptyname);  
    }         

#ifdef SSH_CHANNEL_X11
  ssh_channel_x11_session_destroy(session->x11_placeholder);
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  ssh_channel_agent_session_destroy(session->agent_placeholder);
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  ssh_channel_ssh1_agent_session_destroy(session->ssh1_agent_placeholder);
#endif /* SSH_CHANNEL_SSH1_AGENT */

#ifdef SSH_CHANNEL_TCPFWD
  {
    SshChannelTypeTcpDirect direct_tcp_ctx;
    SshChannelTypeTcpForward forwarded_tcp_ctx;
    SshRemoteTcpForward remote_forwards;
    SshLocalTcpForward local_forwards;
    
    direct_tcp_ctx = ssh_channel_dtcp_ct(common);
    forwarded_tcp_ctx = ssh_channel_ftcp_ct(common);
    
    if (forwarded_tcp_ctx != NULL)
      {
        remote_forwards = forwarded_tcp_ctx->remote_forwards;
        
        for (; remote_forwards;
             remote_forwards = remote_forwards->next)
          {
            if (remote_forwards->listener)
              {
                ssh_tcp_destroy_listener(remote_forwards->listener);
                remote_forwards->listener = NULL;
              }
          }
      }
    
    if (direct_tcp_ctx != NULL)
      {
        local_forwards = direct_tcp_ctx->local_forwards;

        for (; local_forwards;
             local_forwards = local_forwards->next)
          {
            if (local_forwards->listener)
              {
                ssh_tcp_destroy_listener(local_forwards->listener);
                local_forwards->listener = NULL;
              }
          }
      }
  }
#endif /* SSH_CHANNEL_TCPFWD */
  /* Decrement the count of open channels.  Note that this may destroy the
     connection and related objects. */
  ssh_common_destroy_channel(common);

  /* Notify the application that the session has been closed.  Note that
     this may destroy the common object (and the conn protocol). */
  if (session->close_notify)
    (*session->close_notify)(session->context);
  
  /* XXX free dynamic data from session. */
  memset(session, 'F', sizeof(*session));
  ssh_xfree(session);
  
  /* XXX process close after all channels gone... */
}

void ssh_channel_session_eof_callback(void *context)
{
  SshChannelSession session = (SshChannelSession)context;
  long exit_status;
  SshBuffer buffer;

  SSH_DEBUG(5, ("eof received from interactive command - command exited"));
  
  if (!session->active)
    return;

  /* Get the exit status of the child process. */
  if (session->have_pty)
    exit_status = ssh_pty_get_exit_status(session->stream);
  else
    exit_status = ssh_pipe_get_exit_status(session->stream);

  /* Send the exit status (or signal number) in the appropriate message. */
  ssh_buffer_init(&buffer);
  if (exit_status >= 0)
    {
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_UINT32, (SshUInt32) exit_status,
                        SSH_FORMAT_END);
      ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                    "exit-status", ssh_buffer_ptr(&buffer),
                                    ssh_buffer_len(&buffer), NULL, NULL);
    }
  else
    {
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_UINT32, (SshUInt32) -exit_status,
                        SSH_FORMAT_BOOLEAN, FALSE,
                        SSH_FORMAT_UINT32_STR, NULL, 0,
                        SSH_FORMAT_UINT32_STR, NULL, 0,
                        SSH_FORMAT_END);
      ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                    "exit-signal", ssh_buffer_ptr(&buffer),
                                    ssh_buffer_len(&buffer), NULL, NULL);
    }
  ssh_buffer_uninit(&buffer);
}

/* Processes an open request for a session channel. */

void ssh_channel_session_open(const char *type, int channel_id,
                              const unsigned char *data, size_t len,
                              SshConnOpenCompletionProc completion,
                              void *completion_context, void *context)
{
  SshCommon common = (SshCommon)context;
  SshChannelSession session;

  SSH_DEBUG(5, ("session channel open request received"));

  /* Don't allow opening sessions from client to server (at least not until
     it can be configured). */
  if (common->client)
    {
      ssh_warning("Opening a session to client denied.");
      (*completion)(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
      return;
    }
  
  /* Increment the active channel count. */
  ssh_common_new_channel(common);
  
  /* Create a session context. */
  session = ssh_xcalloc(1, sizeof(*session));
  session->common = common;
  session->channel_id = channel_id;
  session->have_pty = FALSE;

#ifdef SSH_CHANNEL_X11
  ssh_channel_x11_session_create(common, &session->x11_placeholder);
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  ssh_channel_agent_session_create(common, &session->agent_placeholder);
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  ssh_channel_ssh1_agent_session_create(common,
                                       &session->ssh1_agent_placeholder);
#endif /* SSH_CHANNEL_SSH1_AGENT */
  
  /* Register an EOF callback for the session. */
  ssh_conn_channel_register_eof_callback(common->conn, channel_id,
                                         ssh_channel_session_eof_callback,
                                         (void *)session);
  
  /* Complete opening the session.  However, creating the stream is postponed
     until we receive a request to start shell/command. */
  (*completion)(SSH_OPEN_OK,
                SSH_CONN_POSTPONE_STREAM, TRUE, TRUE,
                SSH_SESSION_INTERACTIVE_WINDOW,
                NULL, 0,
                ssh_channel_session_request, ssh_channel_session_destroy,
                (void *)session, completion_context);
}

/* Completion function for sending the request to start the shell/command
   for the session channel.  This calls the user callback to return status. */

void ssh_channel_start_session_completion2(Boolean success,
                                          const unsigned char *data,
                                          size_t len,
                                          void *context)
{
  SshChannelSession session = (SshChannelSession)context;
  SshCommon common;
  int i;
  
  SSH_DEBUG(5, ("all session start requests sent"));

  common = session->common;
  
  /* Free any dynamically allocated data related to starting the session. */
  if (session->term != NULL)
    ssh_xfree(session->term);
  if (session->start_command != NULL)
    ssh_xfree(session->start_command);
  if (session->start_env != NULL)
    {
      for (i = 0; session->start_env[i]; i++)
        ssh_xfree(session->start_env[i]);
      ssh_xfree(session->start_env);
    }

  /* We shouldn't get any data in the reply. */
  if (len != 0)
    {
      SSH_DEBUG(0, ("extra data at end of session start request reply"));
      success = FALSE;
    }

  /* If starting the command failed, return failure. */
  if (!success)
    {
      SSH_DEBUG(0, ("starting session failed: result %d", (int)success));
      if (session->start_completion != NULL)
        (*session->start_completion)(FALSE, session->start_context);
      ssh_conn_channel_close(common->conn, session->channel_id);
      /* The session object will be destroyed and the channel count
         decremented in the destroy function. */
      return;
    }

  /* We have successfully opened the channel and executed a command on it. */
  session->active = TRUE;

  /* Call the completion function. */
  if (session->start_completion)
    (*session->start_completion)(TRUE, session->start_context);
}

#ifdef SIGWINCH

/* SIGWINCH (window size change signal) handler.  This sends a window
   change request to the server. */

void ssh_client_win_dim_change(int sig, void *ctx)
{
  struct winsize ws;
  SshBuffer buf;
  SshChannelSession session;
  
  session = (SshChannelSession) ctx;
  
  if (session == NULL || session->common == NULL || 
      session->common->conn == NULL)
    {
      ssh_warning("ssh_client_win_dim_change() failed");
      return;
    }
  
  if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0)
    {
      session->width_chars = ws.ws_col;
      session->height_chars = ws.ws_row;
      session->width_pixels = ws.ws_xpixel;
      session->height_pixels = ws.ws_ypixel;
    }    
  else
    {
      ssh_warning("ssh_client_win_dim_change(): "
                  "unable to get window size parameters.");
      return;
    }

  SSH_DEBUG(5, ("sending a window size change request %lu x %lu",
                session->width_chars, session->height_chars));
  
  ssh_buffer_init(&buf);
  ssh_encode_buffer(&buf,
                    SSH_FORMAT_UINT32, (SshUInt32) session->width_chars,
                    SSH_FORMAT_UINT32, (SshUInt32) session->height_chars,
                    SSH_FORMAT_UINT32, (SshUInt32) session->width_pixels,
                    SSH_FORMAT_UINT32, (SshUInt32) session->height_pixels,
                    SSH_FORMAT_END);
  
  ssh_conn_send_channel_request(session->common->conn, 
                                session->channel_id,
                                "window-change", ssh_buffer_ptr(&buf),
                                ssh_buffer_len(&buf), NULL, NULL);
  ssh_buffer_uninit(&buf);
}
#endif /* SIGWINCH */

/* Completion function for opening the session channel. */

void ssh_channel_start_session_completion(int result,
                                         int channel_id,
                                         const unsigned char *data,
                                         size_t len,
                                         void *context)
{
  SshChannelSession session = (SshChannelSession)context;
  SshCommon common;
  int i;
  SshBuffer buffer;
  unsigned char *modes;
  size_t modes_len;
  struct winsize ws;

  SSH_DEBUG(5, ("session channel established (but requests not yet sent)"));

  common = session->common;
  
  /* If opening the session failed, free the session data structure and
     signal failure to the completion procedure. */
  if (result != SSH_OPEN_OK)
    {
      if (session->start_completion)
        (*session->start_completion)(FALSE, session->start_context);
      if (session->start_auto_close && session->start_stderr_stream != NULL)
        ssh_stream_destroy(session->start_stderr_stream);
      if (session->term != NULL)
        ssh_xfree(session->term);
      if (session->start_command != NULL)
        ssh_xfree(session->start_command);
      if (session->start_env != NULL)
        {
          for (i = 0; session->start_env[i]; i++)
            ssh_xfree(session->start_env[i]);
          ssh_xfree(session->start_env);
        }
      /* The destroy function will get called after this call.  It will free the session object
         and decrement the number of open channels. */
      return;
    }

  /* Channel was successfully created. */
  session->channel_id = channel_id;
  
  /* Register the stderr stream is given. */
  if (session->start_stderr_stream)
    ssh_conn_channel_register_extended(session->common->conn,
                                       session->channel_id,
                                       SSH_EXTENDED_DATA_STDERR,
                                       session->start_stderr_stream,
                                       TRUE, session->start_auto_close);
  
  ssh_encode_tty_flags(fileno(stdin), &modes, &modes_len);
  
  ssh_buffer_init(&buffer);

  session->has_winch_handler = FALSE;
  
  /* Send pty request. */
  if (session->start_allocate_pty)
    {

      if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0)
        {
          session->width_chars = ws.ws_col;
          session->height_chars = ws.ws_row;
          session->width_pixels = ws.ws_xpixel;
          session->height_pixels = ws.ws_ypixel;
        }    
      else
        {
          session->width_chars = 80;
          session->height_chars = 25;
          session->width_pixels = 0;
          session->height_pixels = 0;
        }
      
      ssh_buffer_clear(&buffer);
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_UINT32_STR,
                          session->start_term, strlen(session->start_term),
                        SSH_FORMAT_UINT32, (SshUInt32) session->width_chars,
                        SSH_FORMAT_UINT32, (SshUInt32) session->height_chars,
                        SSH_FORMAT_UINT32, (SshUInt32) session->width_pixels,
                        SSH_FORMAT_UINT32, (SshUInt32) session->height_pixels,
                        SSH_FORMAT_UINT32_STR, modes, modes_len,
                        SSH_FORMAT_END);
      ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                    "pty-req", ssh_buffer_ptr(&buffer),
                                    ssh_buffer_len(&buffer), NULL, NULL);

#ifdef SIGWINCH
      /* Register a signal handler for SIGWINCH to send window change
         notifications to the server. */
      ssh_register_signal(SIGWINCH, ssh_client_win_dim_change, session); 
      session->has_winch_handler = TRUE;
#endif
      ssh_enter_raw_mode(-1);
    }

#ifdef SSH_CHANNEL_X11
  /* X11 forwarding request. */
  if (session->start_forward_x11)
    ssh_channel_x11_send_request(session->common, session->channel_id);
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  /* Agent forwarding request. */
  if (session->start_forward_agent && 
      ((getenv(SSH_AGENT_VAR) != NULL) || (getenv(SSH_AA_VAR) != NULL)))
    ssh_channel_agent_send_request(session->common, session->channel_id);
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  /* Ssh1 agent forwarding request. */
  if (session->start_forward_agent && 
      (session->common->config->ssh_agent_compat != SSH_AGENT_COMPAT_NONE) &&
      (getenv(SSH1_AGENT_VAR) != NULL))
    ssh_channel_ssh1_agent_send_request(session->common, session->channel_id);
#endif /* SSH_CHANNEL_SSH1_AGENT */

  /* Environment variables. */
  if (session->start_env != NULL)
    {
      ssh_debug("ssh_channel_start_session_completion: env not yet impl");
      /* XXX */
    }

  /* Start the command or subsystem. */
  ssh_buffer_clear(&buffer);
  if (session->start_command)
    ssh_encode_buffer(&buffer,
                      SSH_FORMAT_UINT32_STR,
                        session->start_command, strlen(session->start_command),
                      SSH_FORMAT_END);
  if (session->start_is_subsystem)
    ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                  "subsystem", ssh_buffer_ptr(&buffer),
                                  ssh_buffer_len(&buffer),
                                  ssh_channel_start_session_completion2,
                                  (void *)session);
  else
    if (session->start_command != NULL)
      ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                    "exec", ssh_buffer_ptr(&buffer),
                                    ssh_buffer_len(&buffer),
                                    ssh_channel_start_session_completion2,
                                    (void *)session);
    else
      ssh_conn_send_channel_request(session->common->conn, session->channel_id,
                                    "shell", NULL, 0,
                                    ssh_channel_start_session_completion2,
                                    (void *)session);
  ssh_buffer_uninit(&buffer);
}

/* Starts a new command at the remote end.
     `common'       the common protocol object
     `stdio_stream' stream for stdin/stdout data
     `stderr_stream' stream for stderr data, or NULL to merge with stdout
     `auto_close'   automatically close stdio and stderr on channel close
     `is_subsystem' TRUE if command is a subsystem name instead of command
     `command'      command to execute, or NULL for shell
     `allocate_pty' TRUE if pty should be allocated for the command
     `term'         terminal type (e.g. "vt100") when pty, NULL otherwise
     `env'          NULL, or "name=value" strings to pass as environment
     `forward_x11'  TRUE to request X11 forwarding
     `forward_agent' TRUE to request agent forwarding
     `completion'   completion procedure to be called when done (may be NULL)
     `close_notify' function to call when ch closed (may be NULL)
     `context'      argument to pass to ``completion''.
   It is not an error if some forwarding fails, or an environment variable
   passing is denied.  The ``close_notify'' callback will be called
   regardless of the way the session is destroyed - ssh_client_destroy will
   call ``close_notify'' for all open channels.  It is also called if opening
   the cannnel fails.  It is legal to call ssh_conn_destroy from
   ``close_notify'', unless it has already been called. */

void ssh_channel_start_session(SshCommon common, SshStream stdio_stream,
                              SshStream stderr_stream, Boolean auto_close,
                              Boolean is_subsystem, const char *command,
                              Boolean allocate_pty, const char *term,
                              const char **env,
                              Boolean forward_x11, Boolean forward_agent,
                              void (*completion)(Boolean success,
                                                 void *context),
                              void (*close_notify)(void *context),
                              void *context)
{
  SshChannelSession session;
  int i, env_size;

  /* Create the session data structure. */
  session = ssh_xcalloc(1, sizeof(*session));
  session->common = common;
  session->channel_id = -1;

  /* Copy data needed for starting the session. */
  session->start_stderr_stream = stderr_stream;
  session->start_auto_close = auto_close;
  session->start_is_subsystem = is_subsystem;
  session->start_command = command ? ssh_xstrdup(command) : NULL;
  session->start_allocate_pty = allocate_pty;
  session->start_term = term ? ssh_xstrdup(term) : NULL;

  session->close_notify = close_notify;
  session->context = context;

#ifdef SSH_CHANNEL_X11
  ssh_channel_x11_session_create(common, &session->x11_placeholder);
#endif /* SSH_CHANNEL_X11 */

#ifdef SSH_CHANNEL_AGENT
  ssh_channel_agent_session_create(common, &session->agent_placeholder);
#endif /* SSH_CHANNEL_AGENT */

#ifdef SSH_CHANNEL_SSH1_AGENT
  ssh_channel_ssh1_agent_session_create(common, 
                                        &session->ssh1_agent_placeholder);
#endif /* SSH_CHANNEL_SSH1_AGENT */
  
  /* Copy environment. */
  if (env == NULL)
    session->start_env = NULL;
  else
    {
      for (i = 0; env && env[i]; i++)
        ;
      env_size = i;
      session->start_env = ssh_xmalloc((env_size + 1) * sizeof(env[0]));
      for (i = 0; i < env_size; i++)
        session->start_env[i] = ssh_xstrdup(env[i]);
    }

  /* Copy remaining data. */
  session->start_forward_x11 = forward_x11;
  session->start_forward_agent = forward_agent;
  session->start_completion = completion;
  session->start_context = context;

  if (stdio_stream != NULL)
    {
      /* Increment the number of open channels. */
      ssh_common_new_channel(common);
      
      /* Send the channel open request for the session. */
      ssh_conn_send_channel_open(common->conn, "session",
                                 stdio_stream, auto_close, FALSE,
                                 allocate_pty ?
                                 SSH_SESSION_INTERACTIVE_WINDOW :
                                 SSH_SESSION_NONINTERACTIVE_WINDOW,
                                 allocate_pty ?
                                 SSH_SESSION_INTERACTIVE_PACKET_SIZE :
                                 SSH_SESSION_NONINTERACTIVE_PACKET_SIZE,
                                 NULL, 0,
                                 ssh_channel_session_request,
                                 ssh_channel_session_destroy,
                                 (void *)session,
                                 ssh_channel_start_session_completion,
                                 (void *)session);
    }
}

#endif /* SSH_CHANNEL_SESSION */
