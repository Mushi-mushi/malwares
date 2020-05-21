/*

agentpath.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Code for creating a listener to the SSH authentication agent.

*/


#include "ssh2includes.h"
#include "sshsessionincludes.h"
#include "sshtcp.h"
#include "sshagent.h"
#include "sshagentint.h"
#include "sshlocalstream.h"

#define SSH_DEBUG_MODULE "SshAgentPath"

/* Determines the directory in which to place the agent socket.  This
   is unix-specific.  This creates the appropriate directories.  This returns
   FALSE if the directories could not be created with safe modes, and
   TRUE if everything is ok.  The agent socket cannot be safely created
   if this returns FALSE (the path is set in any case). */

Boolean ssh_agenti_determine_path(char *buf, 
                                  size_t buflen, 
                                  uid_t uid,
                                  Boolean ssh1_agent)
{
  struct passwd *pw;
  const char *user;
  char socket_dir_name[100];
  struct stat st;
  int ret;

  pw = getpwuid(uid);
  if (pw)
    user = pw->pw_name;
  else
    user = "unknown";

  snprintf(socket_dir_name, sizeof(socket_dir_name), SSH_AGENT_SOCKET_DIR,
           user);

  snprintf(buf, buflen,
           ((!ssh1_agent)
            ? 
            (SSH_AGENT_SOCKET_DIR "/" SSH_AGENT_SOCKET)
            :
            (SSH_AGENT_SOCKET_DIR "/" SSH1_AGENT_SOCKET)),
           user, (int)getpid());
  
  /* Check that the per-user socket directory either doesn't exist
     or has good modes */
  ret = stat(socket_dir_name, &st);
  if (ret < 0 && errno != ENOENT)
    {
      ssh_warning("ssh_agenti_determine_path: stat %s: %s",
                  socket_dir_name, strerror(errno));
      return FALSE;
    }
  if (ret < 0 && errno == ENOENT)
    {
      if (mkdir(socket_dir_name, S_IRWXU) < 0)
        {
          ssh_warning("ssh_agenti_determine_path: mkdir %s: %s",
                      socket_dir_name, strerror(errno));
          return FALSE;
        }
      else
        {
          (void)chown(socket_dir_name, uid, 0);
        }
    }

  /* Check the owner and permissions */
  if (stat(socket_dir_name, &st) != 0 || st.st_uid != uid ||
      (st.st_mode & 077) != 0)
    {
      ssh_warning("ssh_agenti_determine_path: bad modes or owner for directory '%s'\n",
                  socket_dir_name);
      return FALSE;
    }

  /* Check that socket doesn't exist.  We'll remove it if it does. */
  ret = stat(buf, &st);
  if (ret < 0 && errno != ENOENT)
    {
      ssh_warning("ssh_agenti_determine_path: '%s' already exists - removed",
                  buf);
      remove(buf);
    }

  return TRUE;
}

/* Creates a listener for agent connections for the given uid.  This
   might be a normal socket, or might be a listener for some kind of
   interprocess communication.  This returns NULL if an error occurs.
   If `path_return' is non-NULL, it will be set to point to the path
   name of the created listener (regardless of whether creation was
   successful).  The caller is responsible for freeing it with ssh_xfree
   when no longer needed. */

SshLocalListener ssh_agenti_create_listener(uid_t uid, char **path_return,
                                            SshLocalCallback callback,
                                            Boolean ssh1_agent,
                                            void *context)
{
  char path[100];
  SshLocalListener listener;

  if (!ssh_agenti_determine_path(path, sizeof(path), uid, ssh1_agent))
    {
      if (path_return)
        *path_return = ssh_xstrdup(path);
      return NULL;
    }
  if (path_return)
    *path_return = ssh_xstrdup(path);
  
  listener = ssh_local_make_listener(path, callback, context);

  if (listener)
    {
      (void)chown(path, uid, 0);
      (void)chmod(path, S_IRUSR | S_IWUSR);
    }
  else
    {
      return NULL;
    }

  return listener;
}

/* Connects to an existing authentication agent.  In Unix, this gets
   the path of a unix domain socket from an environment variable and
   connects that socket.  This calls the given function when the connection
   is complete. */

void ssh_agenti_connect(SshLocalCallback callback, 
                        Boolean ssh1_agent,
                        void *context)
{
  const char *path;
  
  /* Get the path of the agent socket. */
  path = getenv((!ssh1_agent) ? SSH_AGENT_VAR : SSH1_AGENT_VAR);
  if (path == NULL)
    {
      path = getenv(SSH_AA_VAR);
    }
  if (path == NULL)
    {
      (*callback)(NULL, context);
      return;
    }

  if (getuid() != geteuid())
    {
      /* XXX much more checking and care is needed to make this work in
         suid programs.  Talk to kivinen@ssh.fi or ylo@ssh.fi before 
         attempting to do anything for that.  Compare with the code in
         ssh-1.22. */
      ssh_warning("ssh_agenti_connect has not been written to work securely in a suid program.");
      ssh_warning("Refusing to connect to agent.");
      (*callback)(NULL, context);
      return;
    }
  
  /* Connect to the agent. */
  ssh_local_connect(path, callback, context);
}
