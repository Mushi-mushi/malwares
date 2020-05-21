/*

sshunixconfig.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Processing configuration data in SSH (both client and server).

*/

#include "ssh2includes.h"
#include "sshconfig.h"
#include "sshuser.h"
#include "sshuserfile.h"
#include "sshuserfiles.h"
#include "sshmatch.h"
#include "sshcipherlist.h"
#include "ssh2pubkeyencode.h"

#define SSH_DEBUG_MODULE "SshUnixConfig"

char *ssh2_config_line_heading_separator(char *linebuf)
{
  char *hlp = linebuf;
  int inquotes = 0;

  while (*hlp) 
    {
      if ((*hlp == ':') && (inquotes == 0))
        return hlp;
      else if (*hlp == '"')
        inquotes = !inquotes;
      hlp++;
    }
  return NULL;
}

void ssh2_config_remove_quotes(char *str)
{
  char *hlp1, *hlp2;
  int in_quotes = 0;
  int quoted = 0;

  hlp1 = hlp2 = str;

  while (*hlp1)
    {
      switch (*hlp1)
        {
        case '"':
          if (quoted)
            {
              *hlp2 = *hlp1;
              hlp2++;
            }
          in_quotes = !in_quotes;
          break;

        case '\\':
          if ((!in_quotes) || quoted)
            {
              *hlp2 = *hlp1;
              hlp2++;
              quoted = 0;
            }
          else
            {
              quoted = 1;
            }
          break;

        default:
          *hlp2 = *hlp1;
          hlp2++;
          quoted = 0;
        }
      hlp1++;
    }
  *hlp2 = '\0';
}

/* Parse a configuration/authorization file into an array of 
   variable name <-> value pairs. Return the number of variables or -1 on 
   error. Pointers to tables of pointers to null-terminated strings are
   placed at *variables and *values. */
int ssh2_parse_config(SshUser user, const char *instance, const char *path, 
                      char ***variables, char ***values, void *context)
{
  SshUserFile f;
  char **vars, **vals, *varpos, *valpos, *hlp;
  char linebuf[1024];
  size_t n;
  int i, j;
  int line, ch;
  Boolean matching;

  if (user == NULL)
    {
      if ((f = ssh_userfile_open(getuid(), path, O_RDONLY, 0755)) == NULL)
        {
          ssh_debug("Unable to open %s", path);
          return -1;
        }
    }
  else
    {
      if ((f = ssh_userfile_open(ssh_user_uid(user), path, O_RDONLY, 0755)) ==
          NULL)
        {
          ssh_debug("Unable to open %s", path);
          return -1;
        }
    }

  line = 0;
  i = 0;
  n = 16;
  matching = TRUE;
  vars = ssh_xcalloc(n, sizeof(char *));
  vals = ssh_xcalloc(n, sizeof(char *));

  while (ssh_userfile_gets(linebuf, sizeof(linebuf) - 1, f) != NULL)
    {
      line++;

      /* skip the starting white spaces and comment lines */

      for (j = 0;; j++)
        {
          ch = linebuf[j];
          if (ch == '\0' || ch == '#')
            goto skip;
          if (!isspace(ch))
            break;
        }
      
      /* see if this is a heading or not.. */
      hlp = ssh2_config_line_heading_separator(linebuf);
      if (hlp != NULL)
        {
          *hlp = '\0';
          matching = ssh_match_pattern(instance, &linebuf[j]);
          continue;
        }

      /* ok, it must be a variable definition */

      if (!matching)
        goto skip;

      varpos = &linebuf[j];

      /* convert the variable name to lower case */

      for (j = 0; varpos[j] && (isalnum(varpos[j]) || varpos[j] == '-'); j++)
        varpos[j] = tolower(varpos[j]);

      if (!varpos[j] || !isspace(varpos[j]))
        {
          ssh_warning("%s: invalid definition in line %d.", 
                      path, line);
          goto skip;
        }
      varpos[j++] = 0;

      for (; varpos[j] && isspace(varpos[j]); j++)
        ;
      valpos = &varpos[j];

      /* remove spaces from the tail */

      for (j = strlen(valpos) - 1; j > 0 && isspace(valpos[j]); j--)
        ;
      valpos[j + 1] = 0;

      vars[i] = ssh_xstrdup(varpos);
      vals[i] = ssh_xstrdup(valpos);
      ssh2_config_remove_quotes(vals[i]);
      i++;

      /* get more space if needed */

      if (i >= n)
        {
          n = 2 * n;
          vars = ssh_xrealloc(vars, n * sizeof(char *));
          vals = ssh_xrealloc(vals, n * sizeof(char *));
        }
    skip:
      ;
    }

  ssh_userfile_close(f);
  *variables = vars;
  *values = vals;

  return i;
}

Boolean ssh_server_load_host_key(SshConfig config,
                                 SshPrivateKey *private_host_key,
                                 unsigned char **public_host_key_blob,
                                 size_t *public_host_key_blob_len,
                                 void *context)
{
  SshUser user;
  char *userdir = NULL, *comment;
  char hostkeyfile[256];
  SshPrivateKey privkey;

  if ((user = ssh_user_initialize(NULL, TRUE)) == NULL)
    ssh_fatal("ssh_server_load_host_key: ssh_user_initialize failed");
      

  /* load the host key from (typically) /etc/ssh2/hostkey */
  if(config->host_key_file[0] != '/')
    {    
      if (ssh_user_uid(user) == 0 )
        {
          userdir = ssh_xstrdup(SSH_SERVER_DIR);
        }
      else
        {
          if ((userdir = ssh_userdir(user, config, TRUE)) == NULL)
            ssh_fatal("ssh_server_load_host_key: no ssh2 user directory");
        }
      
      snprintf(hostkeyfile, sizeof(hostkeyfile), "%s/%s",
               userdir, config->host_key_file);
    }
  else
    {
      snprintf(hostkeyfile, sizeof(hostkeyfile), "%s",
               config->host_key_file);
    }
  
  ssh_debug("Reading private host key from %s", hostkeyfile);
  if ((privkey = ssh_privkey_read(user, hostkeyfile, "", &comment,
                                  NULL)) == NULL)
    ssh_fatal("ssh_privkey_read from %s failed.", hostkeyfile);

  /* print the comment just for fun.. */
  if (comment != NULL)
    {
      if (strlen(comment) > 0)
        ssh_debug("Key comment: %s", comment);
      ssh_xfree(comment);
    }
  *private_host_key = privkey;

  /* ok, now read the public host key blob */
  if(config->public_host_key_file[0] != '/')
    {
      snprintf(hostkeyfile, sizeof(hostkeyfile), "%s/%s", 
               userdir, config->public_host_key_file);
    }
  else
    {
      snprintf(hostkeyfile, sizeof(hostkeyfile), "%s", 
               config->public_host_key_file);
    }
  
  SSH_TRACE(1, ("Reading public host key from: %s", hostkeyfile));

  if (ssh2_key_blob_read(user, hostkeyfile, NULL,
                        public_host_key_blob,
                        public_host_key_blob_len, NULL) 
      != SSH_KEY_MAGIC_PUBLIC)
    ssh_fatal("Unable to load public host key from %s.", hostkeyfile);

  /* check keytype */

  if ((config->public_key_algorithm =
       ssh_pubkeyblob_type(*public_host_key_blob,
                           *public_host_key_blob_len))
      == NULL)
    {
      SSH_TRACE(0, ("Unable to get public key type from %s.", hostkeyfile));
      goto error;
    }
  

  ssh_xfree(userdir);
  ssh_user_free(user, FALSE);

  return TRUE;

 error: 
  ssh_xfree(userdir);
  ssh_user_free(user, FALSE);
  return FALSE;
}


/* Parse a line of input */

Boolean ssh_config_parse_line(SshConfig config, char *line)
{
  int j, k;
  char var[1024], val[1024];

  /* skip over spaces in the beginning */

  for (j = 0; line[j] != '\0' && isspace(line[j]); j++)
    ;
  if (line[j] == '\0')
    return TRUE;
  
  /* convert the variable name to lower case while copying it */
  
  k = 0;
  for (k = 0; k < (sizeof(var)-2) && isalnum(line[j]); j++)
    var[k++] = tolower(line[j]);
  var[k++] = '\0';
  if (!isspace(line[j]))
    return TRUE;
  
  /* skip the spaces in the middle */
  for (; isspace(line[j]); j++)
    ;

  /* determine the actual length of the value */
  for (k = strlen(line); isspace(line[k]); k--)
    ;
  if ((k - j) >= (sizeof(val) - 1) || k == j)
    return TRUE;
  
  /* make a copy of the value */
  memcpy(val, &line[j], k - j);
  val[k - j] = '\0';
  
  /* now we're ready to call ssh_config_set_parameter() */
  
  if (!ssh_config_set_parameter(config, var, val))
    return TRUE;
  
  return FALSE;
}

/* Reads config data from the given file.  Returns FALSE if an error
   occurs (displays error messages with ssh_warning.) */

Boolean ssh_config_read_file(SshUser user, SshConfig config,
                             char *instance, const char *filename,
                             void *context)
{
  SshUser user_data;
  char **vars, **vals;
  int i, n;
  
  if (filename == NULL || strlen(filename) == 0)
    return FALSE;
  
  if (user == NULL)
    user_data = ssh_user_initialize(NULL, FALSE);
  else
    user_data = user;

  /* try to read in the file */
  instance = (instance ? instance : "");

  n = ssh2_parse_config(user_data, instance, filename, &vars, &vals, NULL);

  if (n < 0)
    {
      if (user_data != user)
        ssh_user_free(user_data, FALSE);
      return FALSE;
    }

  /* ok, now fill in the fields */

  for (i = 0; i < n; i++)
    ssh_config_set_parameter(config, vars[i], vals[i]);

  ssh_free_varsvals(n, vars, vals);

  if (user_data != user)
    ssh_user_free(user_data, FALSE);

  return TRUE;
}

/* Parse forwarding definitions. Format is port:remotehost:remoteport */
Boolean ssh_parse_forward(SshForward *forwards, char *spec)
{
  SshForward fwd;
  char *local_port, *host, *port;

  local_port = strtok(spec, ":");
  if (local_port == NULL)
    return TRUE;
  host = strtok(NULL, ":");
  if (host == NULL)
    return TRUE;
  port = strtok(NULL, ":");
  if (port == NULL)
    return TRUE;
  fwd = ssh_xcalloc(1, sizeof(*fwd));
  fwd->local_addr = ssh_xstrdup("0.0.0.0");
  fwd->port = ssh_xstrdup(local_port);
  fwd->connect_to_host = ssh_xstrdup(host);
  fwd->connect_to_port = ssh_xstrdup(port);
  fwd->next = *forwards;
  *forwards = fwd;
  return FALSE;
}  
