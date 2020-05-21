/*

  auth-hostbased-rhosts.c

  Author: Tatu Ylonen <ylo@cs.hut.fi>
          Sami Lehtinen <sjl@ssh.fi>
          
  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Hostbased authentication, server-side. .[sr]hosts and
  /etc/hosts.equiv processing. Based on auth-rhosts.c from ssh-1.2.26.

*/

#include "ssh2includes.h"
#include "sshuserfile.h"
#include "sshuser.h"
#include "sshconfig.h"
#include "sshserver.h"
#include "sshuserfiles.h"
#include "auths-common.h"
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */
#ifdef HAVE_NETGROUP_H
#include <netgroup.h>
#endif /* HAVE_NETGROUP_H */

#define SSH_DEBUG_MODULE "Ssh2AuthHostBasedRhosts"

/* Returns true if the strings are equal, ignoring case (a-z only). */
static Boolean casefold_equal(const char *a, const char *b)
{
  unsigned char cha, chb;
  for (; *a; a++, b++)
    {
      cha = *a;
      chb = *b;
      if (!chb)
        return FALSE;
      if (cha >= 'a' && cha <= 'z')
        cha -= 32;
      if (chb >= 'a' && chb <= 'z')
        chb -= 32;
      if (cha != chb)
        return FALSE;
    }
  return !*b;
}

/* This function processes an rhosts-style file (.rhosts, .shosts, or
   /etc/hosts.equiv).  This returns true if authentication can be granted
   based on the file, and returns zero otherwise.  All I/O will be done
   using the given uid with userfile. */
Boolean check_rhosts_file(uid_t uid, const char *filename,
                          const char *hostname,
                          const char *ipaddr, const char *client_user,
                          const char *server_user, void *context)
{
  SshUserFile uf;
  char buf[1024]; /* Must not be larger than host, user, dummy below. */
  SshServer server = (SshServer) context;
  
  /* Open the .rhosts file. */
  uf = ssh_userfile_open(uid, filename, O_RDONLY, 0);
  if (uf == NULL)
    return FALSE; /* Cannot read the .rhosts - deny access. */

  /* Go through the file, checking every entry. */
  while (ssh_userfile_gets(buf, sizeof(buf), uf))
    {
      /* All three must be at least as big as buf to avoid overflows. */
      char hostbuf[1024], userbuf[1024], dummy[1024], *host, *user, *cp, *c;
      int negated;
      
      for(cp = buf; *cp; cp++)
        {
          if (*cp < 32 && !isspace(*cp))
            {
              SSH_TRACE(2, ("Found control characters in '%s', rest of "\
                            "the file ignored", filename));
              ssh_userfile_close(uf);
              return FALSE;
            }
        }
      for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
        ;
      if ((c = strchr(cp, '#')) != NULL)
        *c = '\0';
      if (*cp == '#' || *cp == '\n' || !*cp)
        continue;

      /* NO_PLUS is supported at least on OSF/1.  We skip it (we don't ever
         support the plus syntax). */
      if (strncmp(cp, "NO_PLUS", 7) == 0)
        continue;

      /* This should be safe because each buffer is as big as the whole
         string, and thus cannot be overwritten. */
      switch (sscanf(buf, "%s %s %s", hostbuf, userbuf, dummy))
        {
        case 0:
          SSH_DEBUG(2, ("Found empty line in %.100s.", filename));
          continue; /* Empty line? */
        case 1:
          /* Host name only. */
          strncpy(userbuf, server_user, sizeof(userbuf));
          userbuf[sizeof(userbuf) - 1] = 0;
          break;
        case 2:
          /* Got both host and user name. */
          break;
        case 3:
          SSH_TRACE(2, ("Found garbage in %.100s.", filename));
          continue; /* Extra garbage */
        default:
          continue; /* Weird... */
        }

      host = hostbuf;
      user = userbuf;
      /* Truncate host and user name to 255 to avoid buffer overflows in system
         libraries */
      if (strlen(host) > 255)
        host[255] = '\0';
      if (strlen(user) > 255)
        user[255] = '\0';
      negated = 0;

      /* Process negated host names, or positive netgroups. */
      if (host[0] == '-')
        {
          negated = 1;
          host++;
        }
      else
        if (host[0] == '+')
          host++;

      if (user[0] == '-')
        {
          negated = 1;
          user++;
        }
      else
        if (user[0] == '+')
          user++;

      /* Check for empty host/user names (particularly '+'). */
      if (!host[0] || !user[0])
        { 
          /* We come here if either was '+' or '-'. */
          SSH_TRACE(2, ("Ignoring wild host/user names in %.100s.", \
                        filename));
          continue;
        }
          
#ifdef HAVE_INNETGR
      
      /* Verify that host name matches. */
      if (host[0] == '@')
        {
          if (!innetgr(host + 1, (char *)hostname, NULL, NULL) &&
              !innetgr(host + 1, (char *)ipaddr, NULL, NULL))
            continue;
        }
      else
        if (!casefold_equal(host, hostname) && strcmp(host, ipaddr) != 0)
          continue; /* Different hostname. */

      /* Verify that user name matches. */
      if (user[0] == '@')
        {
          if (!innetgr(user + 1, NULL, (char *)client_user, NULL))
            continue;
        }
      else
        if (strcmp(user, client_user) != 0)
          continue; /* Different username. */

#else /* HAVE_INNETGR */

      if (!casefold_equal(host, hostname) && strcmp(host, ipaddr) != 0)
        continue; /* Different hostname. */

      if (strcmp(user, client_user) != 0)
        continue; /* Different username. */

#endif /* HAVE_INNETGR */

      /* XXX sync with ssh_server_auth_check_host */
      /* XXX this function is a silly place for this. This should be
         in ssh_server_auth_hostbased_rhosts(), where these checks
         would be performed before coming here. */
      {
        Boolean perm_denied = FALSE;
        
        if (server->config->denied_shosts)
          {
            if (!ssh_match_host_in_list(server->common->remote_host,
                                        server->common->remote_ip,
                                        server->config->denied_shosts))
              perm_denied = TRUE;
          }
      
        if (!perm_denied && server->config->allowed_shosts)
          {
            if (!ssh_match_host_in_list(server->common->remote_host,
                                        server->common->remote_ip,
                                        server->config->allowed_shosts))
              perm_denied = FALSE;
            else
              perm_denied = TRUE;
          }      
      
        /* RequireReverseMapping */
        if (server->config->require_reverse_mapping)
          {
            if (strcmp(server->common->remote_host,
                       server->common->remote_ip) == 0)
              {
                /* If remote host's ip-address couldn't be mapped to a
                   hostname and RequireReverseMapping = 'yes', deny
                   connection.*/
                perm_denied = TRUE;
              }
          }

        if (perm_denied)
          {
            ssh_log_event(server->config->log_facility, SSH_LOG_WARNING,
                          "Use of %s denied for %s", filename, host);
            SSH_TRACE(2, ("Use of %s denied for %s", filename, host));
            continue;
          }
      }
      
      /* Found the user and host. */
      ssh_userfile_close(uf);

      /* If the entry was negated, deny access. */
      if (negated)
        {
          SSH_TRACE(2, ("Matched negative entry in %.100s.", \
                        filename));
          return FALSE;
        }

      /* Accept authentication. */
      return TRUE;
    }
     
  /* Authentication using this file denied. */
  ssh_userfile_close(uf);
  return FALSE;
}

/* Tries to authenticate the user using the .shosts or .rhosts file.
   Returns true if authentication succeeds.  If config->ignore_rhosts
   is true, only /etc/hosts.equiv will be considered (.rhosts and
   .shosts are ignored), unless the user is root and
   config->ignore_root_rhosts isn't true. */
Boolean ssh_server_auth_hostbased_rhosts(SshUser user_data,
                                         const char *client_user,
                                         void *context)
{
  char buf[1024];
  const char *hostname, *ipaddr;
  struct stat st;
  static const char *rhosts_files[] = { ".shosts", ".rhosts", NULL };
  unsigned int rhosts_file_index;
  SshConfig config;
  SshServer server = (SshServer) context;
  SshUser effective_user_data =
    ssh_user_initialize_with_uid(geteuid(), FALSE);
  
  config = server->config;

  ssh_userfile_init(ssh_user_name(user_data), ssh_user_uid(user_data),
                    ssh_user_gid(user_data), NULL, NULL);

  /* Get the name, address, and port of the remote host.  */
  hostname = server->common->remote_host;
  ipaddr = server->common->remote_ip;

  /* Quick check: if the user has no .shosts or .rhosts files, return failure
     immediately without doing costly lookups from name servers. */
  for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
       rhosts_file_index++)
    {
      /* Check users .rhosts or .shosts. */
      snprintf(buf, sizeof(buf), "%.500s/%.100s", 
              ssh_user_dir(user_data), rhosts_files[rhosts_file_index]);
      if (ssh_userfile_stat(ssh_user_uid(user_data), buf, &st) >= 0)
        break;
    }

  if (!rhosts_files[rhosts_file_index] && 
      ssh_userfile_stat(ssh_user_uid(user_data), "/etc/hosts.equiv", &st) < 0 &&
      ssh_userfile_stat(ssh_user_uid(user_data), SSH_HOSTS_EQUIV, &st) < 0)
    return FALSE; /* The user has no .shosts or .rhosts file and there are no
                 system-wide files. */
  
  /* If not logging in as superuser, try /etc/hosts.equiv and shosts.equiv. */
  if (ssh_user_uid(user_data) != UID_ROOT)
    {
      if (check_rhosts_file(ssh_user_uid(effective_user_data), 
                            "/etc/hosts.equiv", hostname, ipaddr, client_user,
                            ssh_user_name(user_data), server))
        {
          SSH_TRACE(2, ("Accepted for %.100s [%.100s] by " \
                        "/etc/hosts.equiv.", hostname, ipaddr));
          return TRUE;
        }
      if (check_rhosts_file(ssh_user_uid(effective_user_data),
                            SSH_HOSTS_EQUIV, hostname, ipaddr, client_user,
                            ssh_user_name(user_data), server))
        {
          SSH_TRACE(2, ("Accepted for %.100s [%.100s] by %.100s.",  \
                            hostname, ipaddr, SSH_HOSTS_EQUIV));
          return TRUE;
        }
    }

  /* Check that the home directory is owned by root or the user, and is not 
     group or world writable. */
  if (ssh_userfile_stat(ssh_user_uid(user_data), ssh_user_dir(user_data),
                    &st) < 0)
    {
      ssh_log_event(config->log_facility, SSH_LOG_WARNING,
                    "hostbased-authentication (rhosts) refused for " \
                    "%.100: no home directory %.200s",
                    ssh_user_name(user_data),
                    ssh_user_dir(user_data));
      SSH_TRACE(2, ("hostbased-authentication (rhosts) refused for " \
                    "%.100: no home directory %.200s", \
                    ssh_user_name(user_data), ssh_user_dir(user_data)));
      return FALSE;
    }
  
  if (config->strict_modes && 
      ((st.st_uid != UID_ROOT && st.st_uid != ssh_user_uid(user_data)) ||
#ifdef ALLOW_GROUP_WRITEABILITY
       (st.st_mode & 002) != 0)
#else
       (st.st_mode & 022) != 0)
#endif
      )
    {
      ssh_log_event(config->log_facility, SSH_LOG_WARNING,
                    "hostbased-authentication (rhosts) refused for " \
                    "%.100s: bad ownership or modes for home directory.",
                    ssh_user_name(user_data));
      SSH_TRACE(2, ("hostbased-authentication (rhosts) refused for " \
                    "%.100s: bad ownership or modes for home directory.", \
                    ssh_user_name(user_data)));
      return FALSE;
    }
  
  /* Check all .rhosts files (currently .shosts and .rhosts). */
  for (rhosts_file_index = 0; rhosts_files[rhosts_file_index];
       rhosts_file_index++)
    {
      /* Check users .rhosts or .shosts. */
      snprintf(buf, sizeof(buf), "%.500s/%.100s", 
              ssh_user_dir(user_data), rhosts_files[rhosts_file_index]);
      if (ssh_userfile_stat(ssh_user_uid(user_data), buf, &st) < 0)
        continue; /* No such file. */

      /* Make sure that the file is either owned by the user or by root,
         and make sure it is not writable by anyone but the owner.  This is
         to help avoid novices accidentally allowing access to their account
         by anyone. */
      if (config->strict_modes &&
          ((st.st_uid != UID_ROOT && st.st_uid != ssh_user_uid(user_data)) ||
           (st.st_mode & 022) != 0))
        {
          ssh_log_event(config->log_facility, SSH_LOG_WARNING,
                        "hostbased-authentication (rhosts) refused for " \
                        "%.100s: bad modes for %.200s",
                        ssh_user_name(user_data), buf);
          SSH_TRACE(2, ("hostbased-authentication (rhosts) refused for " \
                        "%.100s: bad modes for %.200s", \
                        ssh_user_name(user_data), buf));
          continue;
        }

      /* Check if we have been configured to ignore .rhosts and .shosts 
         files.  If root, check ignore_root_rhosts first. */
      if ((ssh_user_uid(user_data) == UID_ROOT &&
           config->ignore_root_rhosts) ||
          (ssh_user_uid(user_data) != UID_ROOT &&
           config->ignore_rhosts))
        {
          SSH_TRACE(2, ("Server has been configured to ignore %.100s.", \
                        rhosts_files[rhosts_file_index]));
          continue;
        }

      /* Check if authentication is permitted by the file. */
      if (check_rhosts_file(ssh_user_uid(user_data), buf, hostname,
                            ipaddr, client_user, ssh_user_name(user_data),
                            server))
        {
          SSH_TRACE(2, ("Accepted by %.100s.", \
                        rhosts_files[rhosts_file_index]));
          return TRUE;
        }
    }

  /* Rhosts authentication denied. */
  SSH_TRACE(2, ("hostbased-authentication (rhosts) refused: client " \
                "user '%.100s', server user '%.100s', " \
                "client host '%.200s'.", \
                client_user, ssh_user_name(user_data), hostname));

  ssh_log_event(config->log_facility, SSH_LOG_WARNING,
                "hostbased-authentication (rhosts) refused: client " \
                "user '%.100s', server user '%.100s', " \
                "client host '%.200s'.", \
                client_user, ssh_user_name(user_data), hostname);

  return FALSE;
}
