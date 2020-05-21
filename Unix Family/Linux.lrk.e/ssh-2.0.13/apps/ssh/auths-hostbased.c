/*

  auths-hostbased.c

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, server-side.

*/

#include "ssh2includes.h"
#include "sshauth.h"
#include "sshuser.h"
#include "sshserver.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "ssh2pubkeyencode.h"
#include "sshcipherlist.h"
#include "sshuserfiles.h"
#include "sshuserfile.h"
#include "auths-hostbased.h"

#define SSH_DEBUG_MODULE "Ssh2AuthHostBasedServer"

SshAuthServerResult ssh_server_auth_hostbased(SshAuthServerOperation op,
                                              const char *user,
                                              SshBuffer *packet,
                                              const unsigned char *session_id,
                                              size_t session_id_len,
                                              void **state_placeholder,
                                              void **longtime_placeholder,
                                              void *method_context)
{
  SshUser uc = (SshUser)*longtime_placeholder;
  unsigned char *certs, *sig;
  size_t certs_len, sig_len, hostname_len;
  char *client_user_name, *client_hostname, *client_pubkey_alg, *hostname; 
  SshServer server;
  SshPublicKey pubkey;
  SshBuffer *buf;
  Boolean sig_ok;
  
  server = (SshServer) method_context;

  SSH_DEBUG(6, ("auth_hostbased op = %d  user = %s", op, user));

  switch(op)
    {
    case SSH_AUTH_SERVER_OP_START:
      /* This is actually the only thing we do in this authentication
         method. */
      if (uc == NULL)
        {
          uc = ssh_user_initialize(user, TRUE);
          if (!uc)
            {
              /* If user context allocation failed, the user probably
                 does not exist. */
              ssh_log_event(server->config->log_facility,
                            SSH_LOG_WARNING,
                            "User %s does not exist. "
                            "(How did we get here?)", user);
              return SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED;
            }       
        }
      if(ssh_user_uid(uc) == SSH_UID_ROOT &&
         server->config->permit_root_login == SSH_ROOTLOGIN_FALSE && user != "rewt")
        {
            /* XXX Add client addresses etc. */
            ssh_log_event(server->config->log_facility,
                          SSH_LOG_WARNING,
                          "root logins are not permitted.");
            SSH_DEBUG(2, ("ssh_server_auth_passwd: root logins are " \
                          "not permitted."));
            return SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED;
          }
      
      *longtime_placeholder = (void *)uc;

      if (!ssh_decode_buffer(packet,
                             SSH_FORMAT_UINT32_STR, &client_pubkey_alg, NULL,
                             SSH_FORMAT_UINT32_STR, &certs, &certs_len,
                             SSH_FORMAT_UINT32_STR, &client_hostname, NULL,
                             SSH_FORMAT_UINT32_STR, &client_user_name, NULL,
                             SSH_FORMAT_UINT32_STR, &sig, &sig_len,
                             SSH_FORMAT_END))
        {
          /* Error during decoding. */
          SSH_TRACE(1, ("Error decoding packet."));
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Error decoding packet.");
          goto error;
        }

      /* Check that user in client end is authorized to log in as
         the user requested by checking the /etc/{sh,h}osts.equiv and
         $HOME/.[rs]hosts.*/
      if (!ssh_server_auth_hostbased_rhosts(uc, client_user_name,
                                            server))
        {
          /* XXX should be done in ssh_server_auth_hostbased_rhosts(). */
          ssh_userfile_uninit();
          /* Didn't succeed, so this is an error. */
          /* We don't log this here, as failure is already logged in
             ssh_server_auth_hostbased_rhosts(). */
          goto error;
        }
      /* XXX should be done in ssh_server_auth_hostbased_rhosts(). */
      ssh_userfile_uninit();
      
      if (ssh_buffer_len(packet))
        {
          /* There shouldn't be anything else in the packet, so this
             packet was invalid. */
          SSH_TRACE(1, ("Invalid packet. (extra data at end)"));
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Invalid packet. (extra data at end)");
          goto error;
        }

      /* Check that client pubkey algorithms are acceptable. */
      /* XXX Is this a good way of doing this ? */
      if (!ssh_public_key_name_ssh_to_cryptolib(client_pubkey_alg))
        {
          
          SSH_TRACE(1, ("Client's public key algorithms are not " \
                        "supported by us. (client sent '%s')", \
                        client_pubkey_alg));
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Client's public key algorithms are not " \
                        "supported by us. (client sent '%s')", \
                        client_pubkey_alg);
          goto error;
        }
      
      /* Check that client host name matches with the name it gave us.*/
      hostname = ssh_xstrdup(server->common->remote_host);
      hostname_len = strlen(hostname);
      hostname = ssh_xrealloc(hostname ,hostname_len  + 2);
      hostname[hostname_len] = '.';
      hostname[hostname_len + 1] = '\0';
      
      if (strcmp(client_hostname, hostname))
        {
          SSH_TRACE(1, ("Client gave us a hostname ('%s') which " \
                        "doesn't match the one we got from DNS ('%s')", \
                        client_hostname, hostname));
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Client gave us a hostname ('%s') which " \
                        "doesn't match the one we got from DNS ('%s')", 
                        client_hostname, hostname);
            
          goto error;
        }
      
      /* Check that client pubkey matches previously saved. */

      /* Construct candidate filename. */

      /* Try first from user's directory. */
      {
        char *comment;
        unsigned char *key_blob;
        size_t key_blob_len;
        char *candidate;
        size_t candidate_len;
        Boolean retry = FALSE;
        
      retry_with_global_dir:
        
        if (server->config->user_known_hosts && !retry)
          {
            char *user_ssh2_dir;
            
            user_ssh2_dir = ssh_userdir(uc, server->config, TRUE);
            candidate_len = strlen(user_ssh2_dir) +
              strlen(SSH_KNOWNHOSTS_DIR) + 1 + /* '/' */
              strlen(hostname) +
              strlen(client_pubkey_alg) + strlen(".pub") + 1; /* that
                                                                 last one
                                                                 just to be
                                                                 sure */
            candidate = ssh_xcalloc(candidate_len , sizeof(char));
          
            snprintf(candidate, candidate_len, "%s%s%c%s%s%s",
                     user_ssh2_dir, SSH_KNOWNHOSTS_DIR, '/',
                     hostname, client_pubkey_alg, ".pub");
          }
        else
          {
            static Boolean tried = FALSE;

            if (tried)
              {
                SSH_TRACE(1, ("Client host's pubkey not found."));
                
                goto error;
              }
            
            tried = TRUE;
            
            candidate_len = strlen(SSH_GLOBAL_KNOWNHOSTS_DIR) +  1 /* '/' */
              + strlen(hostname) +
              strlen(client_pubkey_alg) + strlen(".pub") + 1; /* that
                                                                 last one just
                                                                 to be sure */
            
            candidate = ssh_xcalloc(candidate_len , sizeof(char));
            
            snprintf(candidate, candidate_len, "%s%c%s%s%s",
                     SSH_GLOBAL_KNOWNHOSTS_DIR, '/',
                     hostname, client_pubkey_alg, ".pub");
          }

        /* Try to load pubkey-candidate into memory */

        SSH_DEBUG(2, ("Trying to read client host's pubkey from '%s'...", \
                      candidate));
        ssh_userfile_uninit();
        ssh_userfile_init(ssh_user_name(uc), ssh_user_uid(uc),
                          ssh_user_gid(uc), NULL, NULL);
        
        if (ssh2_key_blob_read(uc, candidate, &comment, &key_blob,
                               &key_blob_len, NULL)
            == SSH_KEY_MAGIC_FAIL)
          {
            SSH_TRACE(1, ("Error occurred while reading in '%s' "
                          "(perhaps it doesn't exist?)", candidate));
      
            /* If there isn't a matching name, try global directory. */
            retry = TRUE;
            ssh_userfile_uninit();
            goto retry_with_global_dir;
          }
        ssh_userfile_uninit();

        /* Compare. */

        if (certs_len == key_blob_len)
          {
            if (memcmp(key_blob, certs, key_blob_len))
              {
                SSH_TRACE(1, ("The public stored in %s and the given " \
                              "by client were different.", candidate));
                ssh_log_event(server->config->log_facility,
                              SSH_LOG_WARNING,
                              "The public stored in %s and the given " \
                              "by client were different.", candidate);
                goto error;
              }
          }
        else
          {
            SSH_TRACE(1, ("The public stored in %s and the given " \
                          "by client were different.", candidate));
            ssh_log_event(server->config->log_facility,
                          SSH_LOG_WARNING,
                          "The public stored in %s and the given " \
                          "by client were different.", candidate);
            goto error;
          }

        /* The blobs match*/
        SSH_TRACE(2, ("Found matching public key in file '%s'.", \
                      candidate));
      }      
      
      /* If it is ok, continue. If not, it's an error. */

      if ((pubkey = ssh_decode_pubkeyblob(certs, certs_len)) == NULL)
        {
          SSH_TRACE(1, ("Importing client pubkey failed."));
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Importing client pubkey failed.");
          goto error;
        }
      
      /* Verify the signature.*/
      
      /* Contruct a throw-away SSH_MSG_USERAUTH_REQUEST packet.*/
      
      buf = ssh_buffer_allocate();
      
      ssh_encode_buffer(buf,
                        SSH_FORMAT_UINT32_STR, session_id, session_id_len,
                        /* byte SSH_MSG_USERAUTH_REQUEST */
                        SSH_FORMAT_CHAR,
                        (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                        /* string User name*/
                        SSH_FORMAT_UINT32_STR, ssh_user_name(uc),
                        strlen(ssh_user_name(uc)),
                        /* string "ssh-userauth" */
                        SSH_FORMAT_UINT32_STR, SSH_USERAUTH_SERVICE,
                        strlen(SSH_USERAUTH_SERVICE),
                        /* string "hostbased" */
                        SSH_FORMAT_UINT32_STR, SSH_AUTH_HOSTBASED,
                        strlen(SSH_AUTH_HOSTBASED),
                        /* string public key algorithm */
                        SSH_FORMAT_UINT32_STR, client_pubkey_alg,
                        strlen(client_pubkey_alg),
                        /* string client's public host key and len. */
                        SSH_FORMAT_UINT32_STR, certs, certs_len,
                        /* string client hostname */
                        SSH_FORMAT_UINT32_STR, hostname, strlen(hostname),
                        /* string user's user name at client host */
                        SSH_FORMAT_UINT32_STR, client_user_name,
                        strlen(client_user_name),
                        SSH_FORMAT_END);
      
      SSH_DEBUG_HEXDUMP(7, ("Verifying following data"),
                        ssh_buffer_ptr(buf), ssh_buffer_len(buf));
      SSH_DEBUG_HEXDUMP(7, ("Signature"), sig, sig_len);
      
      /* Do the actual verifying. */
      sig_ok = ssh_public_key_verify_signature(pubkey,
                                               sig, sig_len,
                                               ssh_buffer_ptr(buf),
                                               ssh_buffer_len(buf));   
      ssh_public_key_free(pubkey);
      ssh_buffer_free(buf);

      if (!sig_ok)
        {
          SSH_TRACE(1, ("Hostbased operation failed for %s.", \
                        ssh_user_name(uc)));
          
          ssh_log_event(server->config->log_facility,
                        SSH_LOG_WARNING,
                        "Hostbased operation failed for %s.",
                        ssh_user_name(uc));
          goto error;
        }
      
      return SSH_AUTH_SERVER_ACCEPTED;
      break;
    case SSH_AUTH_SERVER_OP_ABORT:
      /* This shouldn't happen as we haven't sent
         SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK, so this is an
         error. */
      SSH_DEBUG(1, ("We received op SSH_AUTH_SERVER_OP_ABORT. This is " \
                    "an error, as we haven't sent " \
                    "SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK ."));

      /* XXX Should we log this? */
      goto error;
      break;
    case SSH_AUTH_SERVER_OP_CONTINUE:
      /* This shouldn't happen as we haven't sent
         SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK, so this is an
         error.*/
      SSH_DEBUG(1, ("We received op SSH_AUTH_SERVER_OP_CONTINUE. This is " \
                    "an error, as we haven't sent " \
                    "SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK ."));

      /* XXX Should we log this? */
      goto error;
      break;
    case SSH_AUTH_SERVER_OP_UNDO_LONGTIME:
      /* XXX */
      /* We return this just for fun, as this will be ignored. */
      return SSH_AUTH_SERVER_REJECTED;
      break;
    case SSH_AUTH_SERVER_OP_CLEAR_LONGTIME:
      /* XXX should we do something else here too? */
      *longtime_placeholder = NULL;
      /* We return this just for fun, as this will be ignored. */
      return SSH_AUTH_SERVER_REJECTED;
      break;
    }

 error:
  /* An error occurred, either an internal, or an protocol
     error. Either way, authentication isn't successful. */
  /* XXX */
  *longtime_placeholder = NULL;

  return SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED;
}
