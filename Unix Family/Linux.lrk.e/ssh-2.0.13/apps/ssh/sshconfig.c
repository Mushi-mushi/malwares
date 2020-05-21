/*

sshconfig.c

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
#include "sshcipherlist.h"
#include "namelist.h"
#include "sshdllist.h"

#define SSH_DEBUG_MODULE "SshConfig"

/* separate (commandline)options from their parameters */
void ssh_split_arguments(int argc, char **argv, int *dest_ac, char ***dest_av)
{
  int temp_ac = 0, i;
  char **temp_av;
  
  int alloc = argc + 1;

  temp_av = ssh_xcalloc(alloc, sizeof(char*));
  
  /* count possible options and parameters */
  for (i = 0; i < argc ; i++)
    {
      if ( alloc < temp_ac + 3)
        {
          alloc = temp_ac + 3;
          temp_av = ssh_xrealloc(temp_av, alloc*sizeof(char*));
        }
      
      if (argv[i][0] == '-' || argv[i][0] == '+')
        {
          if(argv[i][1] && argv[i][2])
            {
              temp_av[temp_ac] = ssh_xstrdup(argv[i]);
              temp_av[temp_ac][2] = '\0';
              temp_av[++temp_ac] = ssh_xstrdup(argv[i] + 2);
            }
          else
            {
              temp_av[temp_ac] = ssh_xstrdup(argv[i]);
            }
        }
      else
        {
          temp_av[temp_ac] = ssh_xstrdup(argv[i]);        
        }
      temp_ac++;
    }
  temp_av[ temp_ac ] = NULL;
  (*dest_ac) = temp_ac;
  (*dest_av) = temp_av;
}

/* Free the "vars" and "vals" arrays */

void ssh_free_varsvals(int n, char **vars, char **vals)
{
  int i;

  for (i = 0; i < n; i++)
    {
      ssh_xfree(vars[i]);
      ssh_xfree(vals[i]);
    }
  ssh_xfree(vars);
  ssh_xfree(vals); 
}


/* Parses a given comma-separated list to tokens, which are stored in
   a SshDlList. The list is allocated and returned by this
   function. On error, returns NULL. */
SshDlList ssh_config_parse_list(char *string,
                                SshParameterValidityProc function,
                                void *context)
{
  char *rest;
  char *current;
  SshDlList list;
  
  SSH_PRECOND(string != NULL);

  list = ssh_dllist_allocate();

  rest = string;

  while (strlen(rest) != 0 && (current = ssh_name_list_get_name(rest)) != NULL)
    {
      char *temp;
      int i, j;
      
      rest += strlen(current);
      if (*rest == ',')
        rest++;

      /* strip whitespaces and non-printable characters */
      temp = ssh_xcalloc(strlen(current) + 1, sizeof(char));
      
      for (i = 0, j = 0; i < strlen(current) ; i ++)
        if(isascii(current[i]) && isprint(current[i]) && !isspace(current[i]))
          {
            temp[j] = current[i];
            j++;
          }
      
      temp[j] = '\0';
      ssh_xfree(current);
      current = temp;

      /* If validity function is given, invoke it to check the current
         parameter.*/
      if (function)
        if ((*function)(current, context))
          {
            ssh_xfree(current);
            continue;
          }
      
      if (ssh_dllist_add_item(list, (void *)current, SSH_DLLIST_END) !=
          SSH_DLLIST_OK)
        {
          SSH_DEBUG(0, ("list operation gave error."));
          ssh_dllist_rewind(list);
          while (ssh_dllist_is_empty(list))
            {
              char *to_be_deleted;
              to_be_deleted = ssh_dllist_delete_current(list);
              ssh_xfree(to_be_deleted);
            }

          ssh_dllist_free(list);
          
          return NULL;
        }      
    }

  return list;
}

/* Allocates and initializes a config structure */
SshConfig ssh_config_init(Boolean client)
{
  SshConfig config;
  config = ssh_xcalloc(1, sizeof(*config));
  config->client = client;

  config->private_host_key = NULL;
  config->public_host_key_blob = NULL;
  config->public_host_key_blob_len = 0;

  config->callback_context = NULL;

  config->random_seed_file = ssh_xstrdup(SSH_RANDSEED_FILE);
  config->pgp_public_key_file = ssh_xstrdup(SSH_PGP_PUBLIC_KEY_FILE);
  config->pgp_secret_key_file = ssh_xstrdup(SSH_PGP_SECRET_KEY_FILE);

  config->forward_agent = TRUE;
  config->forward_x11 = TRUE;
  config->password_authentication = -1;
  config->rhosts_authentication = TRUE;
  config->rhosts_pubkey_authentication = TRUE;
  config->pubkey_authentication = -1;
  config->force_ptty_allocation = FALSE;
  config->verbose_mode = FALSE;
  config->compression = FALSE;

  config->allowed_authentications = NULL;
  config->required_authentications = NULL;

  config->user_known_hosts = TRUE;
  config->port = ssh_xstrdup("22");
  config->ciphers = NULL;
  config->user_conf_dir = ssh_xstrdup(SSH_USER_CONFIG_DIRECTORY);
  config->identity_file = ssh_xstrdup(SSH_IDENTIFICATION_FILE);
  config->authorization_file = ssh_xstrdup(SSH_AUTHORIZATION_FILE);

  config->password_prompt = ssh_xstrdup("%U's password: ");
  config->password_guesses = 3;

  config->max_connections = 0;
  
  config->host_to_connect = NULL;
  config->login_as_user = NULL;
  config->local_forwards = NULL;
  config->remote_forwards = NULL;

  config->allowed_hosts = NULL;
  config->denied_hosts = NULL;
  config->allowed_shosts = NULL;
  config->denied_shosts = NULL;
  config->require_reverse_mapping = FALSE;

  config->log_facility = SSH_LOGFACILITY_AUTH;
  
  config->fall_back_to_rsh = TRUE;
  config->use_rsh = TRUE;
  config->batch_mode = FALSE;
  config->strict_host_key_checking = FALSE;
  config->escape_char = ssh_xstrdup("~");
  config->go_background = FALSE;
  config->dont_read_stdin = FALSE;
  config->gateway_ports = FALSE;
  
  config->ignore_rhosts = FALSE;
  config->ignore_root_rhosts = -1;
  config->permit_root_login = SSH_ROOTLOGIN_TRUE;
  config->permit_empty_passwords = FALSE;
  config->strict_modes = TRUE;
  config->quiet_mode = FALSE;
  config->fascist_logging = FALSE;
  config->print_motd = TRUE;
  config->check_mail = TRUE;
  config->keep_alive = TRUE;
  config->no_delay = FALSE;
  config->listen_address = ssh_xstrdup("0.0.0.0");
  config->login_grace_time = 600;
  config->host_key_file = ssh_xstrdup(SSH_HOSTKEY_FILE);
  config->public_host_key_file = ssh_xstrdup(SSH_PUBLIC_HOSTKEY);
  config->forced_command = NULL;

  config->no_subsystems = 0;
  config->subsystems_allocated = 0;
  config->subsystems = NULL;

#ifdef SSH1_COMPATIBILITY
  config->ssh1_path = ssh_xstrdup(client ? SSH1_PATH : SSHD1_PATH);
  config->ssh1compatibility = TRUE;
#else /* SSH1_COMPATIBILITY */
  config->ssh1_path = NULL;
  config->ssh1compatibility = FALSE;  
#endif /* SSH1_COMPATIBILITY */
  config->ssh_agent_compat = SSH_AGENT_COMPAT_NONE;

  config->signer_path = ssh_xstrdup(SSH_SIGNER_PATH);
  return config;
}

/* This should be called after initializing the config-struct
   (ie. after command-line variables have been parsed. This checks,
   that some required members are initialized properly.*/
void ssh_config_init_finalize(SshConfig config)
{
  /* Common. */
  /* "hostbased"-authentication method is not enabled by default. */
  if (!config->allowed_authentications)
    ssh_config_parse_list((char *)SSH_AUTH_PASSWD "," SSH_AUTH_PUBKEY,
                          NULL, NULL);
  
  /* Client. */
  if (config->client)
    {
      /* Nothing here yet! */
    }
  /* Server. */
  else
    {
      /* If IgnoreRootRhosts isn't defined at this stage, assign it to
         the same as IgnoreRhosts. */
      if (config->ignore_root_rhosts == -1)
        config->ignore_root_rhosts = config->ignore_rhosts;
    }  
}

/* Helper function, that destroys a list, and frees it's contents,
   too. */
void ssh_config_free_list(SshDlList list)
{
  char *to_be_deleted;

  if (list == NULL)
    return;
  
  ssh_dllist_rewind(list);
  while (!ssh_dllist_is_empty(list))
    {
      to_be_deleted = ssh_dllist_delete_current(list);
      ssh_xfree(to_be_deleted);
    }
    
  ssh_dllist_free(list);
}

/* Helper function, that combines two lists. dst will receive nodes
   from src, and src will be freed. (so the pointer isn't valid after
   this call.) If one or both arguments are NULL, does nothing. */
void ssh_config_combine_lists(SshDlList dst, SshDlList src)
{
  if (!dst || !src)
    return;
  
  ssh_dllist_rewind(src);
  while (!ssh_dllist_is_empty(src))
    {
      ssh_dllist_add_item(dst, ssh_dllist_delete_current(src), SSH_DLLIST_END);
    }

  ssh_dllist_free(src);
}

/* Frees client configuration data. */
void ssh_config_free(SshConfig config)
{
  int i;
  
  /* free all allocated memory */
  ssh_xfree(config->random_seed_file);
  ssh_xfree(config->pgp_public_key_file);
  ssh_xfree(config->pgp_secret_key_file);

  ssh_xfree(config->port);
  ssh_xfree(config->ciphers);
  ssh_xfree(config->identity_file);
  ssh_xfree(config->authorization_file);
  ssh_xfree(config->escape_char);
  ssh_xfree(config->listen_address);
  ssh_xfree(config->host_key_file);
  ssh_xfree(config->password_prompt);
  ssh_xfree(config->public_host_key_file);

  ssh_xfree(config->host_to_connect);
  ssh_xfree(config->login_as_user);
  ssh_xfree(config->local_forwards);
  ssh_xfree(config->remote_forwards);
  
  ssh_config_free_list(config->allowed_hosts);
  ssh_config_free_list(config->denied_hosts);
  ssh_config_free_list(config->allowed_shosts);
  ssh_config_free_list(config->denied_shosts);
  
  ssh_xfree(config->forced_command);

  /* Free subsystem-strings */  
  if (config->no_subsystems > 0 && config->subsystems != NULL)
    for (i = 0; i < config->no_subsystems; i++)
      ssh_xfree(config->subsystems[i]);
  ssh_xfree(config->subsystems);
      
  /* free the host key */
  if (config->client == FALSE)
    {
      if (config->private_host_key != NULL)
        ssh_private_key_free(config->private_host_key);
      ssh_xfree(config->public_host_key_blob);
    }

  ssh_xfree(config->signer_path);
  memset(config, 0, sizeof(*config));
  ssh_xfree(config);
}


/* Returns default configuration information for the server. */

SshConfig ssh_server_create_config()
{
  return ssh_config_init(FALSE);
}

/* Returns default configuration information for the client. */

SshConfig ssh_client_create_config()
{
  return ssh_config_init(TRUE);
}


struct LogFacility
{
  SshLogFacility facility;
  char *fac_name;
} logfacilities[] =
{
  {SSH_LOGFACILITY_AUTH, "AUTH"},
  {SSH_LOGFACILITY_SECURITY, "SECURITY"},
  {SSH_LOGFACILITY_DAEMON, "DAEMON"},
  {SSH_LOGFACILITY_USER, "USER"},
  {SSH_LOGFACILITY_MAIL, "MAIL"},
  {SSH_LOGFACILITY_LOCAL0, "LOCAL0"},
  {SSH_LOGFACILITY_LOCAL1, "LOCAL1"},
  {SSH_LOGFACILITY_LOCAL2, "LOCAL2"},
  {SSH_LOGFACILITY_LOCAL3, "LOCAL3"},
  {SSH_LOGFACILITY_LOCAL4, "LOCAL4"},
  {SSH_LOGFACILITY_LOCAL5, "LOCAL5"},
  {SSH_LOGFACILITY_LOCAL6, "LOCAL6"},
  {SSH_LOGFACILITY_LOCAL7, "LOCAL7"},
  {-1, NULL}
};

Boolean auth_param_validity(const char *param, void *context)
{
  if (strcasecmp(param, SSH_AUTH_PUBKEY) == 0)
    return FALSE;

  if (strcasecmp(param, SSH_AUTH_PASSWD) == 0)
    return FALSE;

  if (strcasecmp(param, SSH_AUTH_HOSTBASED) == 0)
    return FALSE;

  return TRUE;
}

/* Set the variable corresponding to `var' to `val' in config */

Boolean ssh_config_set_parameter(SshConfig config, char *var, char *val)
{
  Boolean bool;
  unsigned int i;
  int num;
  SshSubsystem ss;
  
  switch (val[0])
    {
    case 'y':  /* for "yes" */
    case 'Y':
    case 't':  /* for "true" */
    case 'T':
    case 'k':  /* for kylla [finnish] :-) */
    case 'K':
      
      bool = TRUE;
      break;
      
    default:
      bool = FALSE;
    }

  num = atoi(val);

  /* These configuration parameters are common for both client and 
     server */

  if (strcmp(var, "forwardagent") == 0)
    {
      config->forward_agent = bool;
      return FALSE;
    }

  if (strcmp(var, "forwardx11") == 0)
    {
      config->forward_x11 = bool;
      return FALSE;
    }

  if (strcmp(var, "allowedauthentications") == 0)
    {
      if (config->password_authentication != -1 &&
          (!config->client /*|| config->verbose_mode XXX not yet
                             implemented in client*/))
        ssh_warning("Defining AllowedAuthentications. Parameter "
                    "PasswordAuthentication (already defined) will be "
                    "ignored.");
      
      if (config->pubkey_authentication != -1 &&
          (!config->client /*|| config->verbose_mode XXX not yet
                             implemented in client*/))
        ssh_warning("Defining AllowedAuthentications. Parameter "
                    "PubkeyAuthentication (already defined) will be "
                    "ignored.");
        
      ssh_config_free_list(config->allowed_authentications);

      if ((config->allowed_authentications =
           ssh_config_parse_list(val, auth_param_validity, NULL))
          == NULL)
        {
          ssh_warning("Parsing of value for AllowedAuthentications failed.");
          return TRUE;
        }
      else
        {    
          return FALSE;
        }      
    }
  
  if (strcmp(var, "requiredauthentications") == 0)
    {
      ssh_config_free_list(config->required_authentications);

      if ((config->required_authentications =
           ssh_config_parse_list(val, auth_param_validity, NULL))
          == NULL)
        {
          ssh_warning("Parsing of value for RequiredAuthentications failed.");
          return TRUE;
        }
      else
        {    
          return FALSE;
        }      
    }

  if (strcmp(var, "passwordauthentication") == 0)
    {
      if (config->allowed_authentications)
        {
          if (!config->client || config->verbose_mode)
            ssh_warning("AllowedAuthentications is already defined, ignoring "
                        "PasswordAuthentication keyword.");
          return TRUE;
        }
      
      config->password_authentication = bool;
      ssh_warning("PasswordAuthentication configuration keyword is "
                  "deprecated. Use AllowedAuthentications.");
      return FALSE;
    }
  
  if (strcmp(var, "rhostsauthentication") == 0)
    {
      config->rhosts_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "rhostspubkeyauthentication") == 0 ||
      strcmp(var, "rhostsrsaauthentication") == 0)
    {
      config->rhosts_pubkey_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "pubkeyauthentication") == 0 ||
      strcmp(var, "rsaauthentication") == 0)
    {
      if (config->allowed_authentications)
        {
          if (!config->client || config->verbose_mode)
            ssh_warning("AllowedAuthentications is already defined, ignoring "
                        "PubkeyAuthentication keyword.");
          return TRUE;
        }

      config->pubkey_authentication = bool;
      ssh_warning("PubkeyAuthentication configuration keyword is "
                  "deprecated. Use AllowedAuthentications.");
      return FALSE;
    }
  
  if (strcmp(var, "port") == 0)
    {
      if (num >= 1 && num < 65536)
        {
          ssh_xfree(config->port);
          config->port = ssh_xstrdup(val);
        }
      else
        {
          ssh_warning("Ignoring illegal port number %s", val);
          return TRUE;
        }
      return FALSE;
    }
  
  if (strcmp(var, "ciphers") == 0)
    {
      SSH_DEBUG(3, ("Got config cipherlist \"%s\"", val));
      ssh_xfree(config->ciphers);
      if (strcasecmp(val, "any") == 0)
        {
          int x;
          char *hlp1, *hlp2;
          
          hlp1 = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(SSH_STD_CIPHERS, hlp1);
          hlp2 = ssh_cipher_list_exclude(config->ciphers, "none");
          ssh_xfree(config->ciphers);
          x = strlen(hlp1) + strlen(hlp2) + 2;
          config->ciphers = ssh_xmalloc(x);
          snprintf(config->ciphers, x, "%s,%s", hlp2, hlp1);
          ssh_xfree(hlp1);
          ssh_xfree(hlp2);
          hlp1 = ssh_cipher_list_canonialize(config->ciphers);
          ssh_xfree(config->ciphers);
          config->ciphers = hlp1;
        }
      else if (strcasecmp(val, "anycipher") == 0)
        {
          int x;
          char *hlp1, *hlp2;
          
          hlp2 = ssh_cipher_get_supported_native();
          hlp1 = ssh_cipher_list_exclude(hlp2, "none");
          ssh_xfree(hlp2);
          config->ciphers = ssh_name_list_intersection(SSH_STD_CIPHERS, hlp1);
          hlp2 = ssh_cipher_list_exclude(config->ciphers, "none");
          ssh_xfree(config->ciphers);
          x = strlen(hlp1) + strlen(hlp2) + 2;
          config->ciphers = ssh_xmalloc(x);
          snprintf(config->ciphers, x, "%s,%s", hlp2, hlp1);
          ssh_xfree(hlp1);
          ssh_xfree(hlp2);
          hlp1 = ssh_cipher_list_canonialize(config->ciphers);
          ssh_xfree(config->ciphers);
          config->ciphers = hlp1;
        }
      else if (strcasecmp(val, "anystd") == 0)
        {
          char *hlp = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(hlp, SSH_STD_CIPHERS);
          ssh_xfree(hlp);
        }
      else if (strcasecmp(val, "anystdcipher") == 0)
        {
          char *hlp = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(hlp, SSH_STD_CIPHERS);
          ssh_xfree(hlp);
          hlp = config->ciphers;
          config->ciphers = ssh_cipher_list_exclude(hlp, "none");
          ssh_xfree(hlp);
        }
      else
        {
          config->ciphers = ssh_cipher_list_canonialize(val);
        }
      SSH_DEBUG(3, ("Final cipherlist \"%s\"", config->ciphers));
      return FALSE;
    }
  
  if (strcmp(var, "userconfigdirectory") == 0)
    {
      ssh_xfree(config->user_conf_dir);
      config->user_conf_dir = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "identityfile") == 0)
    {
      ssh_xfree(config->identity_file);
      config->identity_file = ssh_xstrdup(val);
      return FALSE;
    }
  
  if (strcmp(var, "authorizationfile") == 0)
    {
      ssh_xfree(config->authorization_file);
      config->authorization_file = ssh_xstrdup(val);
      return FALSE;
    }
  
  if (strcmp(var, "randomseedfile") == 0)
    {
      ssh_xfree(config->random_seed_file);
      config->random_seed_file = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "pgppublickeyfile") == 0)
    {
      ssh_xfree(config->pgp_public_key_file);
      config->pgp_public_key_file = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "pgpsecretkeyfile") == 0)
    {
      ssh_xfree(config->pgp_secret_key_file);
      config->pgp_secret_key_file = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "forcepttyallocation") == 0)
    {
      config->force_ptty_allocation = bool;
      return FALSE;
    }
  
  if (strcmp(var, "verbosemode") == 0)
    {
      config->verbose_mode = bool;
      if (bool)
        ssh_debug_set_level_string("2");
      return FALSE;
    }

  if (strcmp(var, "quietmode") == 0)
    {
      config->quiet_mode = bool;
      return FALSE;
    }

  if (strcmp(var, "fascistlogging") == 0)
    {
      config->fascist_logging = bool;
      return FALSE;
    }
  
  if (strcmp(var, "keepalive") == 0)
    {
      config->keep_alive = bool;
      return FALSE;
    }

  if (strcmp(var, "nodelay") == 0)
    {
      config->no_delay = bool;
      return FALSE;
    }

  if (strcmp(var, "ssh1compatibility") == 0)
    {
      config->ssh1compatibility = bool;
      return FALSE;
    }
  
  /* for client only */

  if (config->client == TRUE)
    {
      if (strcmp(var, "host") == 0)
        {
          ssh_xfree(config->host_to_connect);
          config->host_to_connect = ssh_xstrdup(val);
          return FALSE;
        }
      if (strcmp(var, "user") == 0)
        {
          ssh_xfree(config->login_as_user);
          config->login_as_user = ssh_xstrdup(val);
          return FALSE;
        }
      if (strcmp(var, "compression") == 0)
        {
          config->compression = bool;
          return FALSE;
        }

      if (strcmp(var, "fallbacktorsh") == 0)
        {
          config->fall_back_to_rsh = bool;
          return FALSE;
        }
  
      if (strcmp(var, "usersh") == 0)
        {
          config->use_rsh = bool;
          return FALSE;
        }
      
      if (strcmp(var, "batchmode") == 0)
        {
          config->batch_mode = bool;
          return FALSE;
        }
      
      if (strcmp(var, "stricthostkeychecking") == 0)
        {
          config->strict_host_key_checking = bool;
          return FALSE;
        }
      
      if (strcmp(var, "escapechar") == 0)
        {
          ssh_xfree(config->escape_char);
          config->escape_char = ssh_xstrdup(val);
          return FALSE;
        }
      
      if (strcmp(var, "passwordprompt") == 0)
        {
          ssh_xfree(config->password_prompt);
          config->password_prompt = ssh_xstrdup(val);
          return FALSE;
        }

      if (strcmp(var, "gobackground") == 0)
        {
          config->go_background = bool;
          return FALSE;
        }
      
      if (strcmp(var, "dontreadstdin") == 0)
        {
          config->dont_read_stdin = bool;
          return FALSE;
        }

      if (strcmp(var, "ssh1path") == 0)
        {
          ssh_xfree(config->ssh1_path);
          config->ssh1_path = ssh_xstrdup(val);
          return FALSE;
        }

      if (strcmp(var, "ssh1agentcompatibility") == 0)
        {
          if (strcasecmp(val, "none") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_NONE;
              return FALSE;
            }
          else if (strcasecmp(val, "traditional") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_TRADITIONAL;
              return FALSE;
            }
          else if (strcasecmp(val, "ssh2") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_SSH2;
              return FALSE;
            }
          else
            {
              ssh_warning("Bad Ssh1AgentCompatibility definition \"%s\"", 
                          val);
              return TRUE;
            }
        }

      if (strcmp(var, "localforward") == 0)
        {
          if(ssh_parse_forward(&(config->local_forwards), val))
            {
              ssh_warning("Bad LocalForward definition \"%s\"", val);
              return TRUE;
            }
          return FALSE;
        }

      if (strcmp(var, "remoteforward") == 0)
        {
          if(ssh_parse_forward(&(config->remote_forwards), val))
            {
              ssh_warning("Bad RemoteForward definition \"%s\"", val);
              return TRUE;
            }
          return FALSE;
        }  
      if (strcmp(var, "sshsignerpath") == 0)
        {
          ssh_xfree(config->signer_path);
          config->signer_path = ssh_xstrdup(val);
          return FALSE;
        }

      if (strcmp(var, "gatewayports") == 0)
        {
          config->gateway_ports = bool;
          return FALSE;
        }
    }
  else
    {
      /* These parameters are only for the server */

      if (strcmp(var, "allowhosts") == 0)
        {
          SshDlList temp;
          
          if ((temp = ssh_config_parse_list(val, NULL, NULL))
              == NULL)
            {
              ssh_warning("Parsing of value for AllowHosts failed.");
              return TRUE;
            }
          else
            {
              if (config->allowed_hosts)
                /* Allow the use of multiple AllowHosts directives. */
                ssh_config_combine_lists(config->allowed_hosts, temp);
              else
                config->allowed_hosts = temp;

              return FALSE;
            }
        }

      if (strcmp(var, "denyhosts") == 0)
        {
          SshDlList temp;
          
          if ((temp = ssh_config_parse_list(val, NULL, NULL))
              == NULL)
            {
              ssh_warning("Parsing of value for DenyHosts failed.");
              return TRUE;
            }
          else
            {
              if (config->denied_hosts)
                /* Allow the use of multiple DenyHosts directives. */
                ssh_config_combine_lists(config->denied_hosts, temp);
              else
                config->denied_hosts = temp;
                  
              return FALSE;
            }
        }
      
      if (strcmp(var, "allowshosts") == 0)
        {
          SshDlList temp;
          
          if ((temp = ssh_config_parse_list(val, NULL, NULL))
              == NULL)
            {
              ssh_warning("Parsing of value for AllowSHosts failed.");
              return TRUE;
            }
          else
            {
              if (config->allowed_hosts)
                /* Allow the use of multiple AllowSHosts directives. */
                ssh_config_combine_lists(config->allowed_shosts, temp);
              else
                config->allowed_shosts = temp;

              return FALSE;
            }
        }

      if (strcmp(var, "denyshosts") == 0)
        {
          SshDlList temp;
          
          if ((temp = ssh_config_parse_list(val, NULL, NULL))
              == NULL)
            {
              ssh_warning("Parsing of value for DenySHosts failed.");
              return TRUE;
            }
          else
            {
              if (config->denied_shosts)
                /* Allow the use of multiple DenyHosts directives. */
                ssh_config_combine_lists(config->denied_shosts, temp);
              else
                config->denied_shosts = temp;
                  
              return FALSE;
            }
        }

      if (strcmp(var, "requirereversemapping") == 0)
        {
          config->require_reverse_mapping = bool;
          return FALSE;
        }

      if (strcmp(var, "userknownhosts") == 0)
        {
          config->user_known_hosts = bool;
          return FALSE;
        }
      
      if (strcmp(var, "syslogfacility") == 0)
        {         
          for (i = 0; logfacilities[i].fac_name != NULL; i++)
            {
              if (strcasecmp(logfacilities[i].fac_name, val) == 0)
                {
                  config->log_facility = logfacilities[i].facility;
                  return FALSE;
                }
            }
          ssh_warning("Unknown SyslogFacility \"%s\".", val);
          return TRUE;
        }
      
      if (strcmp(var, "ignorerhosts") == 0)
        {
          config->ignore_rhosts = bool;
          return FALSE;
        }

      if (strcmp(var, "ignorerootrhosts") == 0)
        {
          config->ignore_root_rhosts = bool;
          return FALSE;
        }
      
      if (strcmp(var, "permitrootlogin") == 0)
        {
          if (strcmp(val, "nopwd") == 0)
            config->permit_root_login = SSH_ROOTLOGIN_NOPWD;
          else
            config->permit_root_login = bool;
          
          return FALSE;
        }
      
      if (strcmp(var, "permitemptypasswords") == 0)
        {
          config->permit_empty_passwords = bool;
          return FALSE;
        }
      
      if (strcmp(var, "strictmodes") == 0)
        {
          config->strict_modes = bool;
          return FALSE;
        }
      
      if (strcmp(var, "printmotd") == 0)
        {
          config->print_motd = bool;
          return FALSE;
        }

      if (strcmp(var, "checkmail") == 0)
        {
          config->check_mail = bool;
          return FALSE;
        }      

      if (strcmp(var, "listenaddress") == 0)
        {
          /* XXX some checks here */
          ssh_xfree(config->listen_address);
          config->listen_address = ssh_xstrdup(val);
          return FALSE;
        }
      
      if (strcmp(var, "hostkeyfile") == 0)
        {
          ssh_xfree(config->host_key_file);
          config->host_key_file = ssh_xstrdup(val);

          /* Note: if you specify PublicHostKeyFile first in the config file,
             and HostKey after that, and you give it the value of 
             SSH_PUBLIC_HOSTKEY (which, at the moment, is the same as 
             SSH_HOSTKEY_FILE with ".pub" appended) the value of 
             config->public_host_key_file will be config->host_key_file with 
             ".pub" appended. This is a minor problem. This kludge here is to 
             avoid changing the value of PublicHostKeyFile depending on the 
             order in which config parameters lie in the configfile. */

          if (strcmp(config->public_host_key_file, SSH_PUBLIC_HOSTKEY) == 0)
            {
              ssh_xfree(config->public_host_key_file);
              num = strlen(val) + strlen(".pub") + 1;
              config->public_host_key_file = ssh_xcalloc(1, num);
              snprintf(config->public_host_key_file, num, "%s.pub", val);
            }
          return FALSE;
        }
      
      if (strcmp(var, "publichostkeyfile") == 0)
        {
          ssh_xfree(config->public_host_key_file);
          config->public_host_key_file = ssh_xstrdup(val);
          return FALSE;
        }
          
      if (strcmp(var, "logingracetime") == 0)
        {
          if (num < 0)
            {
              ssh_warning("Ignoring illegal login grace time %d",
                          num);
              return TRUE;
            }
          config->login_grace_time = num;
          return FALSE;
        }
      
      if (strcmp(var, "passwordguesses") == 0)
        {
          config->password_guesses = num;
          return FALSE;
        }

      if (strcmp(var, "maxconnections") == 0)
        {
          config->max_connections = num;
          return FALSE;
        }

      if (strcmp(var, "sshd1path") == 0)
        {
          ssh_xfree(config->ssh1_path);
          config->ssh1_path = ssh_xstrdup(val);
          return FALSE;
        }


      
      /* Parse subsystem definitions */
      if (strncmp(var, SUBSYSTEM_PREFIX, SUBSYSTEM_PREFIX_LEN) == 0)
        {
          if (strlen(val) < 1)
            {
              ssh_warning("Missing subsystem path");
              return TRUE;
            }
              
          if (config->no_subsystems > 0)
            {
              for (i = 0; i < config->no_subsystems; i++)
                if (strcmp(&var[SUBSYSTEM_PREFIX_LEN], 
                           config->subsystems[i]->name) == 0)
                  {
                    ssh_xfree(config->subsystems[i]->path);
                    config->subsystems[i]->path = ssh_xstrdup(val);
                    ssh_warning("Multiple definitions for subsystem %s",
                                config->subsystems[i]->name);
                    return FALSE; 
                  }
            }
          
          if (config->subsystems_allocated == 0 || 
              (config->no_subsystems + 1) >= config->subsystems_allocated)
            {
              if (config->subsystems_allocated < 4)
                config->subsystems_allocated = 4;
              else
                config->subsystems_allocated *= 2;
              
              config->subsystems = 
                ssh_xrealloc(config->subsystems,
                             config->subsystems_allocated * sizeof (*ss));
            }
          
          ss = ssh_xmalloc(sizeof (*ss));
          ss->name = ssh_xstrdup(&var[SUBSYSTEM_PREFIX_LEN]);
          ss->path = ssh_xstrdup(val);
          config->subsystems[config->no_subsystems++] = ss;
                          
          return FALSE;
        }
      
    }
  ssh_warning("Unrecognized configuration parameter %s", var);
  return TRUE;
}
