 /*

  sshunixuserfiles.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Simple functions that update user's files. These are unix-spesific.

*/

/* 
 * $Log: sshunixuserfiles.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshuserfiles.h"
#include "sshencode.h"
#include "ssh2pubkeyencode.h"
#include "sshuser.h"
#include "sshuserfile.h"
#include "sshconfig.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshUnixUserFiles"

/* Return a pointer to user's ssh2 directory.
   The directory is created if `create_if_needed' is TRUE. 
   Return NULL on failure. The caller is responsible for freeing the returned
   value with ssh_xfree when no longer needed. */

char *ssh_userdir(SshUser user, SshConfig config, Boolean create_if_needed)
{
  char *sshdir;
  struct stat st;

  /* create the .ssh2 directory name */

  sshdir = ssh_user_conf_dir(config, user);

  if (stat(sshdir, &st) < 0)
    {
      if (create_if_needed)
        {
          if (mkdir(sshdir, 0755) < 0)
            {
              SSH_DEBUG(2, ("could not create user's ssh directory %s", 
                            sshdir));
              ssh_xfree(sshdir);
              return NULL;
            }  
        }
      else
        {
          ssh_xfree(sshdir);
          return NULL;
        }
    }

  return sshdir;
}


/* Make sure that the random seed file exists and return a pointer to it. 
   return NULL on failure. The file name is found from `config'. 
   If `config' is NULL, use the standard SSH_RANDSEED_FILE.

   The caller is responsible for freeing the returned value with ssh_xfree 
   when no longer needed. */

char *ssh_randseed_file(SshUser user, SshConfig config)
{
  SshUserFile f;
  char *sshdir, *sshseed;
  size_t sshseedlen;
  struct stat st;
  
  /* XXX config is not used */

  /* See if the random seed directory exists */
  
  if ((sshdir = ssh_userdir(user, config, TRUE)) == NULL)
    return NULL;
  sshseedlen = sizeof(SSH_RANDSEED_FILE) + strlen(sshdir) + 4;
  sshseed = ssh_xmalloc(sshseedlen);
  snprintf(sshseed, sshseedlen, "%s/%s", sshdir, SSH_RANDSEED_FILE);

  /* If it doesn't exist, create it. */

  if (ssh_userfile_stat(ssh_user_uid(user), sshseed, &st) < 0)
    {
      if ((f = ssh_userfile_open(ssh_user_uid(user), sshseed, 
                                 O_RDWR | O_CREAT, 0600)) == NULL)
        {
          SSH_DEBUG(2, ("Could not create random seed file %s.", sshseed));
          ssh_xfree(sshdir);
          ssh_xfree(sshseed);
          return NULL;
        }
      ssh_userfile_close(f);
    }
  
  ssh_xfree(sshdir);

  return sshseed;
}

/* Get the random state from the file.  This loads and merges any data
   in the seed file into the generator. */

void ssh_randseed_load(SshUser user, SshRandomState random_state,
                       SshConfig config)
{
  int i;
  SshUserFile f;
  unsigned char randbuf[16];
  char *sshseed;
  size_t nbytes;

  /* Stir a bit.  This will add a couple of bits of new randomness to the 
     pool. */
  for (i = 0; i < 3; i++)
    ssh_random_stir(random_state);
  
  /* Stir the seed file in, if possible. */
  sshseed = ssh_randseed_file(user, config);
  if ((f = ssh_userfile_open(ssh_user_uid(user), sshseed, O_RDONLY, 0)) != 
      NULL)
    {
      while ((nbytes = ssh_userfile_read(f, randbuf, sizeof(randbuf))) > 0)
        ssh_random_add_noise(random_state, randbuf, nbytes);
      ssh_userfile_close(f);
    }
  ssh_xfree(sshseed); 
  
  /* Stir a bit.  This will add a few bits of new randomness to the pool. */
  for (i = 0; i < 3; i++)
    ssh_random_stir(random_state);
}

/* Updates the random seed file with information from the random
   number generator.  Information from the old random seed file and
   the generator is mixed, so that the new random seed file will
   contain traces of both the generator state and the old seed
   file. */

void ssh_randseed_update(SshUser user, SshRandomState rs, SshConfig config)
{
  size_t i;
  SshUserFile f;
  char *sshseed;
  unsigned char seed[SSH_RANDSEED_LEN];

  /* Load the old random seed file and mix it into the generator. */
  ssh_randseed_load(user, rs, config);
  
  /* Write data from the generator into the random seed file. */
  sshseed = ssh_randseed_file(user, config);
  if ((f = ssh_userfile_open(ssh_user_uid(user), sshseed, O_CREAT | O_WRONLY, 
                         0600)) == NULL)
    {
      SSH_DEBUG(2, ("unable to write the random seed file!"));
      goto error;
    }
  for (i = 0; i < SSH_RANDSEED_LEN; i++)
    seed[i] = ssh_random_get_byte(rs);
  if (ssh_userfile_write(f, seed, SSH_RANDSEED_LEN) != SSH_RANDSEED_LEN)
    ssh_warning("unable to write to the random seed file %s.", sshseed);

  memset(seed, 0, SSH_RANDSEED_LEN);
  ssh_userfile_close(f);

error:
  ssh_xfree(sshseed);
}


/* Reads a blob into a buffer. Return TRUE on failure.  The caller must free
   `*blob' with ssh_xfree when no longer needed. */

Boolean ssh_blob_read(SshUser user, const char *fname, unsigned char **blob, 
                      size_t *bloblen, void *context)
{
  SshUserFile f;
  unsigned char *data;
  struct stat st;
  size_t datalen;

  *bloblen = 0;
  *blob = NULL;

  if (ssh_userfile_stat(ssh_user_uid(user), fname, &st) < 0)
    {
      SSH_DEBUG(2, ("file %s does not exist.", fname));
      return TRUE;
    }
  
  datalen = st.st_size;
  data = ssh_xmalloc(datalen);

  if ((f = ssh_userfile_open(ssh_user_uid(user), fname, O_RDONLY, 0)) == NULL) 
    {
      SSH_DEBUG(2, ("Could not open %s.", fname));
      ssh_xfree(data);
      return TRUE;
    }

  if (ssh_userfile_read(f, data, datalen) != datalen)
    {
      SSH_DEBUG(2, ("Error while reading %s.", fname));
      memset(data, 0, datalen);
      ssh_xfree(data);
      ssh_userfile_close(f); 
      return TRUE;
    }

  ssh_userfile_close(f);
  *blob = data;
  *bloblen = datalen;

  return FALSE;
}


/* Write a blob. Return TRUE on failure. */

Boolean ssh_blob_write(SshUser user, const char *fname, mode_t mode,
                       const unsigned char *blob, size_t bloblen, 
                       void *context)
{
  SshUserFile f;

  if ((f = ssh_userfile_open(ssh_user_uid(user), fname, O_WRONLY | O_CREAT, 
                         mode)) == NULL)
    {
      SSH_DEBUG(2, ("could not open %s.", fname));
      return TRUE;
    }

  if(ssh_userfile_write(f, blob, bloblen) != bloblen)
    {
      SSH_DEBUG(2, ("failed to write %s.", fname));
      return TRUE;
    }

  ssh_userfile_close(f);

  return FALSE;
}

/* build a list of private key files that should be tried when
   logging into `host'.  The list's last entry will be NULL.
   The caller should free the array and all strings in it when no longer
   needed. */

struct SshConfigPrivateKey **ssh_privkey_list(SshUser user, 
                                              char *host, 
                                              SshConfig config)
{
  int i, j, n;
  char *udir, **vars, **vals, buf[1024];
  struct SshConfigPrivateKey **prkey;
#ifdef WITH_PGP
  char *pgp_secret_key_file;
#endif /* WITH_PGP */

  if ((udir = ssh_userdir(user, config, TRUE)) == NULL)
    {
      SSH_DEBUG(2, ("no user directory."));
      return NULL;
    }

  /* read and sort the names */

  snprintf(buf, sizeof(buf)-1, "%s/%s", udir, 
           config == NULL || config->identity_file == NULL ?
           SSH_IDENTIFICATION_FILE : config->identity_file);
  n = ssh2_parse_config(user, host, buf, &vars, &vals, NULL);

  if (n < 0)
    {
      ssh_xfree(udir);
      return NULL;
    }

  /* construct a name list with complete file paths */

  prkey = ssh_xcalloc(n + 1, sizeof (struct SshConfigPrivateKey *));

#ifdef WITH_PGP
  pgp_secret_key_file = ssh_xstrdup(config->pgp_secret_key_file);
#endif /* WITH_PGP */

  j = 0;
  for (i = 0; i < n; i++)
    {
      if (strcmp(vars[i], "idkey") == 0)
        {
          snprintf(buf, sizeof(buf), "%s/%s",
                   udir, vals[i]);
          prkey[j] = ssh_xcalloc(1, sizeof (struct SshConfigPrivateKey));
          prkey[j]->keyfile = ssh_xstrdup(buf);
          j++;
        }
#ifdef WITH_PGP
      else if (strcmp(vars[i], "pgpsecretkeyfile") == 0)
        {
          ssh_xfree(pgp_secret_key_file);
          pgp_secret_key_file = ssh_xstrdup(vals[i]);
        }
      else if (strcmp(vars[i], "idpgpkeyid") == 0)
        {
          unsigned long id;
          char *endptr = NULL;

          id = strtoul(vals[i], &endptr, 0);
          if (((*(vals[0])) != '\0') && ((*endptr) == '\0'))
            {
              snprintf(buf, sizeof(buf), "%s/%s",
                       udir, pgp_secret_key_file);
              prkey[j] = ssh_xcalloc(1, sizeof (struct SshConfigPrivateKey));
              prkey[j]->pgp_keyring = ssh_xstrdup(buf);
              prkey[j]->pgp_id = id;
              j++;
            }
          else
            {
              SSH_DEBUG(2, ("invalid pgp key id number \"%s\"", vals[i]));
            }
        }
      else if (strcmp(vars[i], "idpgpkeyname") == 0)
        {
          snprintf(buf, sizeof(buf), "%s/%s",
                   udir, pgp_secret_key_file);
          prkey[j] = ssh_xcalloc(1, sizeof (struct SshConfigPrivateKey));
          prkey[j]->pgp_keyring = ssh_xstrdup(buf);
          prkey[j]->pgp_name = ssh_xstrdup(vals[i]);
          j++;
        }
      else if (strcmp(vars[i], "idpgpkeyfingerprint") == 0)
        {
          snprintf(buf, sizeof(buf), "%s/%s",
                   udir, pgp_secret_key_file);
          prkey[j] = ssh_xcalloc(1, sizeof (struct SshConfigPrivateKey));
          prkey[j]->pgp_keyring = ssh_xstrdup(buf);
          prkey[j]->pgp_fingerprint = ssh_xstrdup(vals[i]);
          j++;
        }
#endif /* WITH_PGP */
    }
  prkey[j++] = NULL;
  ssh_free_varsvals(n, vars, vals);
  ssh_xfree(udir);
#ifdef WITH_PGP
  ssh_xfree(pgp_secret_key_file);
#endif /* WITH_PGP */

  return prkey;
}

char *ssh_user_conf_dir(SshConfig config, SshUser user)
{
  const char *user_str;
  char *conf_dir;
  unsigned long x;
  char buf[32];
  char *tmp;

  /* Get template from config data */
  conf_dir = ssh_xstrdup((config && config->user_conf_dir) ? 
                         config->user_conf_dir : SSH_USER_CONFIG_DIRECTORY);

  /* Replace %D with home directory */
  user_str = ssh_user_dir(user);
  tmp = ssh_replace_in_string(conf_dir, 
                              "%D", (user_str != NULL) ? user_str : "");
  ssh_xfree(conf_dir);
  conf_dir = tmp;

  /* Ssh_Replace %U with user login name */
  user_str = ssh_user_name(user);
  tmp = ssh_replace_in_string(conf_dir, 
                              "%U", (user_str != NULL) ? user_str : "");
  ssh_xfree(conf_dir);
  conf_dir = tmp;

  /* Ssh_Replace %IU with user ID number */
  x = (unsigned long)ssh_user_uid(user);
  snprintf(buf, sizeof (buf), "%lu", x);
  tmp = ssh_replace_in_string(conf_dir, 
                              "%IU", (user_str != NULL) ? user_str : "");
  ssh_xfree(conf_dir);
  conf_dir = tmp;

  /* Ssh_Replace %IG with group ID number */
  x = (unsigned long)ssh_user_gid(user);
  snprintf(buf, sizeof (buf), "%lu", x);
  tmp = ssh_replace_in_string(conf_dir, 
                              "%IG", (user_str != NULL) ? user_str : "");
  ssh_xfree(conf_dir);
  conf_dir = tmp;

  return conf_dir;
}
