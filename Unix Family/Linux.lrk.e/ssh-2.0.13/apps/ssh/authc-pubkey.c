/*
  
  authc-pubkey.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Public key authentication, client side.
  
*/

#include "ssh2includes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "readpass.h"
#include "ssh2pubkeyencode.h"
#include "sshuserfiles.h"
#include "sshmsgs.h"
#include "sshclient.h"
#include "sshdebug.h"
#include "sshagent.h"
#ifdef WITH_PGP
#include "sshpgp.h"
#include "ssh2pgp.h"
#endif /* WITH_PGP */

#define SSH_DEBUG_MODULE "Ssh2AuthPubKeyClient"

/* Information about a candidate key to be used for authentication.
   Candidate keys may either be in private key files, or may be used
   through the authentication agent. */
typedef struct SshClientPubkeyAuthCandidateRec
{
  /* Type of this candidate.  The key may be available either from a
     key file, or from the authentication agent. */
  enum { CANDIDATE_KEYFILE, 
#ifdef WITH_PGP
         CANDIDATE_PGPKEY,
#endif /* WITH_PGP */
         CANDIDATE_AGENT
  } type;

  /* The public key blob for this candidate (may contain certificates).
     This field is allocated using ssh_xmalloc. */
  unsigned char *pubkeyblob;
  size_t pubkeyblob_len;

  /* the public key algorithm for this key (the type of the key) */
  unsigned char *pubkey_alg;
  
  /* Name of the file containing the private key, if of type
     CANDIDATE_KEYFILE.  This string is allocated using ssh_xmalloc,
     or is NULL. */
  char *privkeyfile;

#ifdef WITH_PGP
  /* If type is CANDIDATE_PGPKEY, the following variables contain 
     secret keyblob in pgp packet format. */
  unsigned char *pgp_seckey;
  size_t pgp_seckey_len;
  char *pgp_keyname;
#endif /* WITH_PGP */
} *SshClientPubkeyAuthCandidate;
  
/* A context for public key authentication, this is stored in 
   *state_placeholder */
typedef struct SshClientPubkeyAuthContextRec
{
  /* Connection to the authentication agent.  This is NULL if we don't have
     an open connection to the agent. */
  SshAgent agent;
  
  /* If the state is SSH_AUTH_CLIENT_PUBKEY_TRYING_KEYS, this
     is the index of the last candidate that we have tried. */
  unsigned int last_tried_candidate;

  /* Number of candidate keys to try for authentication. */
  unsigned int num_candidates;

  /* An array of candidate keys to try for authentication.  Keys are stored
     in order of preference; in particular, keys available from the agent
     are stored in the beginning of the array. */
  SshClientPubkeyAuthCandidate candidates;

  /* Context information for the ongoing authentication request. */
  SshAuthClientCompletionProc completion;
  void *completion_context;
  void **state_placeholder;
  char *user; /* must free with ssh_xmalloc if non-NULL. */
  SshClient client;
} *SshClientPubkeyAuth;

/* Frees the authentication context and any memory referenced from it.  Also
   closes the agent connection if open. */

void ssh_client_auth_pubkey_free_ctx(SshClientPubkeyAuth state)
{
  int i;

  if (state == NULL)
    return;

  /* Close the agent connection if open. */
  if (state->agent)
    ssh_agent_close(state->agent);

  /* Free the candidates array. */
  for (i = 0; i < state->num_candidates; i++)
    {
      ssh_xfree(state->candidates[i].pubkeyblob);
      ssh_xfree(state->candidates[i].privkeyfile);      
      ssh_xfree(state->candidates[i].pubkey_alg);
#ifdef WITH_PGP
      ssh_xfree(state->candidates[i].pgp_seckey);
      ssh_xfree(state->candidates[i].pgp_keyname);
#endif /* WITH_PGP */
    }
  ssh_xfree(state->candidates);
  ssh_xfree(state->user);
            
  /* Free the state structure itself. */
  ssh_xfree (state);
}

/* Constructs a SSH_MSG_USERAUTH_REQUEST that basically asks if a 
   given private key can be used for login. Returns NULL on failure. */

SshBuffer *ssh_client_auth_pubkey_try_key_packet(SshClientPubkeyAuthCandidate c,
                                                 Boolean draft_incompatibility)
{
  SshBuffer *b;

  /* Format the request packet. */
  b = ssh_buffer_allocate();

  if (!draft_incompatibility)
    {
      ssh_encode_buffer(b,
                        SSH_FORMAT_BOOLEAN, FALSE,
                        SSH_FORMAT_UINT32_STR, c->pubkey_alg,
                        strlen((char *)c->pubkey_alg),
                        SSH_FORMAT_UINT32_STR, c->pubkeyblob, c->pubkeyblob_len,
                        SSH_FORMAT_END);
    }
  else
    {      
      /* Remote end has publickey draft incompatibility bug. */
      ssh_encode_buffer(b,
                        SSH_FORMAT_BOOLEAN, FALSE,
                        /* Against the draft. Here should be string
                           'publickey algorithm'*/
                        SSH_FORMAT_UINT32_STR, c->pubkeyblob, c->pubkeyblob_len,
                        SSH_FORMAT_END);
    }
  
  return b;
}                                             

/* Completion procedure for signing with the authentication agent.  This is
   also called after normal local signing is complete.  `result' is the
   signature.  This will construct the packet to be sent to the server,
   and call the authentication method completion procedure (stored in
   state->completion).  The context is a pointer to the state object. */

void ssh_client_auth_pubkey_sign_complete(SshAgentError error,
                                          const unsigned char *result,
                                          size_t len,
                                          void *context)
{
  /* XXX What if the error == SSH_AGENT_ERROR_FAILURE ? We should probably
     do something reasonable here.*/

  SshClientPubkeyAuth state = (SshClientPubkeyAuth)context;
  SshClientPubkeyAuthCandidate c;
  SshBuffer *b;

  /* Get pointer to the candidate being tried. */
  c = &state->candidates[state->last_tried_candidate];
  
  SSH_DEBUG_HEXDUMP(7, ("auth_pubkey_sign_complete: signature:"), result, len);

  /* Construct the body of the message to send to the server. */
  b = ssh_buffer_allocate();

  if (!(*state->client->compat_flags->publickey_draft_incompatility))
    {
        ssh_encode_buffer(b,
                          SSH_FORMAT_BOOLEAN, TRUE,
                          SSH_FORMAT_UINT32_STR, c->pubkey_alg,
                          strlen(c->pubkey_alg),
                          SSH_FORMAT_UINT32_STR, c->pubkeyblob,
                          c->pubkeyblob_len,
                          SSH_FORMAT_UINT32_STR, result, len,
                          SSH_FORMAT_END);
    }
  else
    {      
      /* Remote end has publickey draft incompatibility bug. */
      ssh_encode_buffer(b,
                        SSH_FORMAT_BOOLEAN, TRUE,
                        /* Against the draft. Here should be string
                           'publickey algorithm'*/
                        SSH_FORMAT_UINT32_STR, c->pubkeyblob, c->pubkeyblob_len,
                        SSH_FORMAT_UINT32_STR, result, len,
                        SSH_FORMAT_END);
      }
    
  /* Detach the state structure from the state_placeholder. */
  *state->state_placeholder = NULL;
  
  /* Call the authentication method completion procedure. */
  (*state->completion)(SSH_AUTH_CLIENT_SEND, state->user, b,
                       state->completion_context);

  /* Free the buffer */
  ssh_buffer_free(b);

  /* Free the state. */
  ssh_client_auth_pubkey_free_ctx(state);
}


SshPrivateKey ssh_authc_pubkey_privkey_read(SshUser user,
                                            const char *fname,
                                            const char *passphrase,
                                            char **comment)
{
  SshPrivateKey privkey;
  char buf[256];
  char *pass;

  if (passphrase)
    {
      privkey = ssh_privkey_read(user, fname, passphrase, comment, NULL);
      if (privkey != NULL)
        return privkey;
    }

  privkey = ssh_privkey_read(user, fname, "", comment, NULL);
  if (privkey != NULL)
    return privkey;

  snprintf(buf, sizeof (buf),
           "Passphrase for key \"%s\"%s%s%s",
           fname,
           *comment ? " with comment \"" : ":",
           *comment ? *comment : "",
           *comment ? "\":" : "");

  pass = ssh_read_passphrase(buf , FALSE);

  if (pass && *pass)
    {
      privkey = ssh_privkey_read(user, fname, pass, NULL, NULL);
      memset(pass, 'F', strlen(pass));
      ssh_xfree(pass);
      if (privkey != NULL)
        return privkey;
    }

  return NULL;
}

#ifdef WITH_PGP
SshPrivateKey ssh_authc_pubkey_pgpprivkey_import(unsigned char *blob,
                                                 size_t blob_len,
                                                 const char *passphrase,
                                                 const char *comment)
{
  SshPgpSecretKey pgpkey;
  SshPrivateKey key;
  size_t dlen;
  char buf[256];
  char *pass;

  if (passphrase == NULL)
    dlen = ssh_pgp_secret_key_decode(blob, 
                                     blob_len,
                                     &pgpkey);
  else
    dlen = ssh_pgp_secret_key_decode_with_passphrase(blob, 
                                                     blob_len, 
                                                     passphrase,
                                                     &pgpkey);
  if (dlen == 0)
    {
      return NULL;
    }
  if (pgpkey->key != NULL)
    {
      if (ssh_private_key_copy(pgpkey->key, &key) != SSH_CRYPTO_OK)
        {
          ssh_pgp_secret_key_free(pgpkey);
          return NULL;
        }
      ssh_pgp_secret_key_free(pgpkey);
      return key;
    }
  else
    {
      ssh_pgp_secret_key_free(pgpkey);
    }
  snprintf(buf, sizeof (buf),
           "Passphrase for pgp key%s%s%s: ",
           comment ? " \"" : "",
           comment ? comment : "",
           comment ? "\"" : "");
  pass = ssh_read_passphrase(buf , FALSE);
  if (pass && *pass)
    {
      dlen = ssh_pgp_secret_key_decode_with_passphrase(blob, 
                                                       blob_len, 
                                                       pass,
                                                       &pgpkey);
      memset(pass, 'F', strlen(pass));
      ssh_xfree(pass);
      if (dlen == 0)
        {
          return NULL;
        }
      if (pgpkey->key != NULL)
        {
          if (ssh_private_key_copy(pgpkey->key, &key) != SSH_CRYPTO_OK)
            {
              ssh_pgp_secret_key_free(pgpkey);
              return NULL;
            }
          ssh_pgp_secret_key_free(pgpkey);
          return key;
        }
      else
        {
          ssh_pgp_secret_key_free(pgpkey);
          return NULL;
        }
    }
  return NULL;
}
#endif /* WITH_PGP */


/* Constructs the data to be signed in a public key authentication request.
   Eventually calls state->completion when done. Returns FALSE if reading
   private key was successful and there are candidates left, TRUE if
   not. (note that even if other operations fail, this returns FALSE.)*/

Boolean ssh_client_auth_pubkey_send_signature(SshClientPubkeyAuth state,
                                              const char *user,
                                              unsigned char *session_id,
                                              size_t session_id_len,
                                              SshRandomState random_state)
{
  SshClientPubkeyAuthCandidate c;
  SshPrivateKey privkey;
  SshCryptoStatus code;
  unsigned char *signaturebuf, *packet;
  char * key_comment = NULL;
  char *pubkeytype;
  
  size_t signaturebuflen, signaturelen, packet_len;

  SSH_TRACE(2, ("ssh_client_auth_pubkey_send_signature"));

  c = &state->candidates[state->last_tried_candidate];     

  /* Construct a throw-away SSH_MSG_USERAUTH_REQUEST message for signing. */

  if (!(*state->client->compat_flags->publickey_draft_incompatility))
    {

      /* Get the public key type. */
      pubkeytype = ssh_pubkeyblob_type(c->pubkeyblob, c->pubkeyblob_len);
      
      packet_len = ssh_encode_alloc(&packet,
                                    SSH_FORMAT_DATA, session_id, session_id_len,
                                    SSH_FORMAT_CHAR,
                                    (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                    SSH_FORMAT_UINT32_STR, user, strlen(user),
                                    SSH_FORMAT_UINT32_STR, SSH_USERAUTH_SERVICE,
                                    strlen(SSH_USERAUTH_SERVICE),
                                    SSH_FORMAT_UINT32_STR, SSH_AUTH_PUBKEY,
                                    strlen(SSH_AUTH_PUBKEY),
                                    SSH_FORMAT_BOOLEAN, TRUE,
                                    SSH_FORMAT_UINT32_STR, pubkeytype,
                                    strlen(pubkeytype),
                                    SSH_FORMAT_UINT32_STR, c->pubkeyblob,
                                    c->pubkeyblob_len,
                                    SSH_FORMAT_END);
      
      ssh_xfree(pubkeytype);
    }
  else
    {      
      /* Remote end has publickey draft incompatibility bug. */
      packet_len = ssh_encode_alloc(&packet,
                                    SSH_FORMAT_DATA, session_id, session_id_len,
                                    SSH_FORMAT_CHAR,
                                    (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                    SSH_FORMAT_UINT32_STR, user, strlen(user),
                                    SSH_FORMAT_UINT32_STR, SSH_USERAUTH_SERVICE,
                                    strlen(SSH_USERAUTH_SERVICE),
                                    /* against the draft. Here should
                                       be 'string "publickey"'*/
                                    SSH_FORMAT_BOOLEAN, TRUE,
                                    /* against the draft. Here should
                                       be 'string public key algorith
                                       name'*/
                                    SSH_FORMAT_UINT32_STR, c->pubkeyblob,
                                    c->pubkeyblob_len,
                                    SSH_FORMAT_END);
  
    }

  /* Now sign the buffer.  How to do this depends on the type of the key. */
  switch (c->type)
    {
    case CANDIDATE_AGENT:
      /* Sanity check: the agent should be open. */
      assert(state->agent != NULL);

      /* Send the data to the agent for signing. */
      ssh_agent_op(state->agent, SSH_AGENT_HASH_AND_SIGN,
                   c->pubkeyblob, c->pubkeyblob_len,
                   packet, packet_len,
                   ssh_client_auth_pubkey_sign_complete, (void *)state);

      /* Free the data to be signed.  The agent will call _sign_complete
         once a response has been received.  Note that state is no longer
         necessarily valid when we get here. */
      ssh_xfree(packet);
      return FALSE;

    case CANDIDATE_KEYFILE:
#ifdef WITH_PGP
    case CANDIDATE_PGPKEY:
#endif /* WITH_PGP */

      switch (c->type)
        {
        case CANDIDATE_KEYFILE:
          SSH_TRACE(2, ("ssh_client_auth_pubkey_send_signature: reading %s",
                        c->privkeyfile));
          privkey = ssh_authc_pubkey_privkey_read(state->client->user_data,
                                                  c->privkeyfile,
                                                  NULL,
                                                  &key_comment);
          ssh_xfree(key_comment);
          break;
      
#ifdef WITH_PGP
        case CANDIDATE_PGPKEY:
          SSH_TRACE(2, 
                    ("ssh_client_auth_pubkey_send_signature: import pgpkey"));
          privkey = ssh_authc_pubkey_pgpprivkey_import(c->pgp_seckey,
                                                       c->pgp_seckey_len,
                                                       NULL,
                                                       c->pgp_keyname);
          break;
#endif /* WITH_PGP */

        default:
          SSH_NOTREACHED;
        }
      if (privkey == NULL)
        {
          /* The user probably gave the wrong passphrase. If this is the
             case, move to the next candidate. If we have tried all of
             them, notify the completion procedure.*/
          if (state->last_tried_candidate + 1 < state->num_candidates)
            {
              return TRUE;
            }

          ssh_client_auth_pubkey_sign_complete(SSH_AGENT_ERROR_FAILURE,
                                               NULL, 0, (void *)state);
          return FALSE;
        }

      SSH_DEBUG_HEXDUMP(7, ("auth_pubkey_send_signature: signing:"),
                        packet, packet_len);

      /* Use the private key to sign the data. */
      signaturebuflen = ssh_private_key_max_signature_output_len(privkey);
      signaturebuf = ssh_xmalloc(signaturebuflen);
      code = ssh_private_key_sign(privkey, 
                                  packet,
                                  packet_len,
                                  signaturebuf,
                                  signaturebuflen,
                                  &signaturelen,
                                  random_state);

      /* Check whether the operation was successful. */
      if (code != SSH_CRYPTO_OK)
        {
          ssh_debug("Private key operation failed: %s (%s)",
                    c->privkeyfile, ssh_crypto_status_message(code));
          ssh_xfree(packet);
          ssh_xfree(signaturebuf);
          ssh_private_key_free(privkey);
          /* Tell the completion procedure that we failed. */
          ssh_client_auth_pubkey_sign_complete(SSH_AGENT_ERROR_FAILURE,
                                               NULL, 0, (void *)state);
          /* Note that state is no longer necessarily valid. */
          return FALSE;
        }

      /* Pass the result to the completion procedure. */
      ssh_client_auth_pubkey_sign_complete(SSH_AGENT_ERROR_OK,
                                           signaturebuf, signaturelen,
                                           (void *)state);
      /* Free allocated data.  Note that state is no longer necessarily
         valid. */
      ssh_xfree(signaturebuf);
      ssh_xfree(packet);
      return FALSE;

    default:
      ssh_fatal("ssh_client_auth_pubkey_send_signature: bad type %d",
                (int)c->type);

      /* NOTREACHED */
    }
  return FALSE; /* NOTREACHED */
}

/* Tries the authentication method indicated by state->last_tried_candidate.
   If there is no such candidate, fails authentication. */

void ssh_client_auth_pubkey_try_this_candidate(SshClientPubkeyAuth state)
{
  SshBuffer *b;
  SshClientPubkeyAuthCandidate c;
  
  do
    {
      /* If we have tried all candidates, fail this authentication method. */
      if (state->last_tried_candidate >= state->num_candidates)
        {
          *state->state_placeholder = NULL;
          (*state->completion)(SSH_AUTH_CLIENT_FAIL, state->user, NULL,
                               state->completion_context);
          ssh_client_auth_pubkey_free_ctx(state);
          return;
        }

      /* Construct the first challenge packet */
      c = &state->candidates[state->last_tried_candidate];
      b = ssh_client_auth_pubkey_try_key_packet(c,
                                                *state->client->compat_flags->
                                                publickey_draft_incompatility);
    }
  while (b == NULL);

  /* Probe whether the key is acceptable. */
  (*state->completion)(SSH_AUTH_CLIENT_SEND_AND_CONTINUE_MULTIPLE,
                       state->user, b, state->completion_context);
  ssh_buffer_free(b);
}

/* Adds a key obtained from the agent to the list of candidates.
   This copies the certificates. */

void ssh_client_auth_pubkey_add_agent(SshClientPubkeyAuth state,
                                      const unsigned char *certs,
                                      size_t certs_len)
{
  SshClientPubkeyAuthCandidate c;
  char *pubkey_alg;

  if (certs_len == 0)
    return; /* Skip the URL keys. */
  pubkey_alg = ssh_pubkeyblob_type(certs, certs_len);
  if (pubkey_alg == NULL)
    return; /* Skip unknown pk alg types. */

  /* Extend the candidates array. */
  state->candidates =
    ssh_xrealloc(state->candidates,
                 (state->num_candidates + 1) * sizeof(state->candidates[0]));

  /* Get a pointer to the new candidate. */
  c = &state->candidates[state->num_candidates];

  /* Initialize the new candidate, copying memory for the certificate blob. */
  c->type = CANDIDATE_AGENT;
  c->pubkeyblob = ssh_xmalloc(certs_len);
  memcpy(c->pubkeyblob, certs, certs_len);
  c->pubkeyblob_len = certs_len;
  c->pubkey_alg = pubkey_alg;
  c->privkeyfile = NULL;
#ifdef WITH_PGP
  c->pgp_keyname = NULL;
  c->pgp_seckey = NULL;
#endif
  /* Increase the number of candidates. */
  state->num_candidates++;
}

/* Adds a key file to the list of candidates.  This copies the file name. */

void ssh_client_auth_pubkey_add_keyfile(SshClientPubkeyAuth state,
                                        const char *privkeyfile)
{
  SshClientPubkeyAuthCandidate c;
  unsigned long magic;
  char buf[500];
  unsigned char *certs;
  size_t certs_len;
  char *pubkey_alg;

  /* Read the public key blob from the file. */
  snprintf(buf, sizeof(buf), "%s.pub", privkeyfile);
  magic = ssh2_key_blob_read(state->client->user_data, buf, NULL,
                            &certs, &certs_len, NULL);
  if (magic != SSH_KEY_MAGIC_PUBLIC)
    {
      ssh_warning("Could not read public key file %s", buf);
      return;
    }

  pubkey_alg = ssh_pubkeyblob_type(certs, certs_len);
  if (pubkey_alg == NULL)
    {
      ssh_warning("Could not use public key file %s", buf);
      ssh_xfree(certs);
      return;
    }

  /* Extend the candidates array. */
  state->candidates =
    ssh_xrealloc(state->candidates,
                 (state->num_candidates + 1) * sizeof(state->candidates[0]));

  /* Get a pointer to the new candidate. */
  c = &state->candidates[state->num_candidates];

  /* Initialize the new candidate, copying memory for the certificate blob. */
  c->type = CANDIDATE_KEYFILE;
  c->pubkeyblob = certs;
  c->pubkeyblob_len = certs_len;
  c->pubkey_alg = pubkey_alg;
  c->privkeyfile = ssh_xstrdup(privkeyfile);
#ifdef WITH_PGP
  c->pgp_keyname = NULL;
  c->pgp_seckey = NULL;
#endif

  /* Increase the number of candidates. */
  state->num_candidates++;
}

#ifdef WITH_PGP
void ssh_client_auth_pubkey_add_pgpkey(SshClientPubkeyAuth state,
                                       const char *keyring,
                                       const char *name,
                                       const char *fingerprint,
                                       SshUInt32 id)
{
  SshClientPubkeyAuthCandidate c;
  unsigned char *blob;
  size_t blob_len;
  unsigned char *public_blob;
  size_t public_blob_len;
  Boolean found;
  SshPgpSecretKey secret_key;
  char *comment = NULL;
  char *pubkey_alg;

  if (name)
    found = ssh2_find_pgp_secret_key_with_name(state->client->user_data,
                                               keyring,
                                               name,
                                               &blob,
                                               &blob_len,
                                               &comment);
  else if (fingerprint)
    found = ssh2_find_pgp_secret_key_with_fingerprint(state->client->user_data,
                                                      keyring,
                                                      fingerprint,
                                                      &blob,
                                                      &blob_len,
                                                      &comment);
  else
    found = ssh2_find_pgp_secret_key_with_id(state->client->user_data,
                                             keyring,
                                             id,
                                             &blob,
                                             &blob_len,
                                             &comment);
  if (! found)
    {
      ssh_warning("Could not find pgp key");
      return;
    }
  if (ssh_pgp_secret_key_decode(blob, blob_len, &secret_key) == 0)
    {
      ssh_warning("Could not decode pgp key");
      memset(blob, 'F', blob_len);
      ssh_xfree(blob);
      ssh_xfree(comment);
      return;
    }
  if ((public_blob_len = ssh_encode_pubkeyblob(secret_key->public_key->key,
                                               &public_blob)) == 0)
    {
      ssh_warning("Could not encode pgp key to ssh2 keyblob");
      memset(blob, 'F', blob_len);
      ssh_xfree(blob);
      ssh_xfree(comment);
      return;
    }
  ssh_pgp_secret_key_free(secret_key);

  pubkey_alg = ssh_pubkeyblob_type(public_blob, public_blob_len);
  if (pubkey_alg == NULL)
    {
      ssh_warning("Could not get pk algorithm name from pgp key");
      ssh_xfree(public_blob);
      memset(blob, 'F', blob_len);
      ssh_xfree(blob);
      ssh_xfree(comment);
      return;
    }

  /* Extend the candidates array. */
  state->candidates =
    ssh_xrealloc(state->candidates,
                 (state->num_candidates + 1) * sizeof(state->candidates[0]));

  /* Get a pointer to the new candidate. */
  c = &state->candidates[state->num_candidates];

  /* Initialize the new candidate, copying memory for the certificate blob. */
  c->type = CANDIDATE_PGPKEY;
  c->pubkeyblob = public_blob;
  c->pubkeyblob_len = public_blob_len;
  c->pubkey_alg = pubkey_alg;
  c->privkeyfile = NULL;
  c->pgp_keyname = comment;
  c->pgp_seckey = blob;
  c->pgp_seckey_len = blob_len;

  /* Increase the number of candidates. */
  state->num_candidates++;

  return;
}
#endif /* WITH_PGP */

/* This completion function is called during the initialization of public
   key authentication when a list of keys supported by the agent has been
   obtained (the call is faked if we have no agent). */

void ssh_client_auth_pubkey_agent_list_complete(SshAgentError error,
                                                unsigned int num_keys,
                                                SshAgentKeyInfo keys,
                                                void *context)
{
  SshClientPubkeyAuth state = (SshClientPubkeyAuth)context;
  unsigned int i;
  struct SshConfigPrivateKey **privkey;

  SSH_DEBUG(3, ("ssh_client_auth_pubkey_agent_list_complete err %d num %d",
                (int)error, (int)num_keys));

  /* Display a warning if we couldn't get the list. */
  if (error != SSH_AGENT_ERROR_OK)
    {
      ssh_warning("Obtaining a list of keys from the authentication agent failed.");
      num_keys = 0;
    }

  /* Add all obtained keys as candidates for authentication. */
  for (i = 0; i < num_keys; i++)
    ssh_client_auth_pubkey_add_agent(state, keys[i].certs, keys[i].certs_len);

  /* Construct a list of private key files that may be used to log in. */
  privkey = ssh_privkey_list(state->client->user_data, 
                             state->client->common->server_host_name,
                             state->client->common->config);

  /* If there are no suitable keys on our part, terminate early. */
  if (privkey != NULL)
    {
      for (i = 0; privkey[i]; i++)
        {
          if (privkey[i]->keyfile)
            {
              SSH_DEBUG(2, ("adding keyfile \"%s\" to candidates", 
                            privkey[i]->keyfile));
              ssh_client_auth_pubkey_add_keyfile(state, privkey[i]->keyfile);
            }
#ifdef WITH_PGP
          else if (privkey[i]->pgp_keyring)
            {
              SSH_DEBUG(2, 
                        ("adding pgpkeyfile f=\"%s\" n=\"%s\" p=\"%s\" "
                         "i=0x%08lx to candidates", 
                         privkey[i]->pgp_keyring,
                         (privkey[i]->pgp_name ? 
                          privkey[i]->pgp_name : 
                          ""),
                         (privkey[i]->pgp_fingerprint ? 
                          privkey[i]->pgp_fingerprint : 
                          ""),
                         privkey[i]->pgp_id));
              ssh_client_auth_pubkey_add_pgpkey(state,
                                                privkey[i]->pgp_keyring,
                                                privkey[i]->pgp_name,
                                                privkey[i]->pgp_fingerprint,
                                                privkey[i]->pgp_id);
            }
#endif /* WITH_PGP */
          ssh_xfree(privkey[i]->keyfile);
#ifdef WITH_PGP
          ssh_xfree(privkey[i]->pgp_keyring);
          ssh_xfree(privkey[i]->pgp_name);
          ssh_xfree(privkey[i]->pgp_fingerprint);
#endif /* WITH_PGP */
          ssh_xfree(privkey[i]);
        }
      ssh_xfree(privkey);
    }

  /* Set the candidate to try.  Note that this may be equal to the number
     of candidates if we have none. */
  state->last_tried_candidate = 0;

  /* Try this candidate. */
  ssh_client_auth_pubkey_try_this_candidate(state);
}

/* This completion function is called during the initialization of public
   key authentication when opening a connection to the agent is complete.
   If a connection was successful, `agent' will be the agent handle.
   Otherwise, `agent' will be NULL.  `context' points to the state object. */

void ssh_client_auth_pubkey_agent_open_complete(SshAgent agent, void *context)
{
  SshClientPubkeyAuth state = (SshClientPubkeyAuth)context;

  SSH_DEBUG(4, ("ssh_client_auth_pubkey_agent_open_complete agent=0x%lx",
                (unsigned long)agent));
  
  if (agent)
    {
      /* A connection to the agent was successfully opened.  Save the
         handle. */
      state->agent = agent;

      /* Request a list of keys supported by the agent. */
      ssh_agent_list(agent, ssh_client_auth_pubkey_agent_list_complete,
                     (void *)state);
    }
  else
    {
      /* No agent.  Fake a callback to the agent list completion, with no
         keys. */
      ssh_client_auth_pubkey_agent_list_complete(SSH_AGENT_ERROR_OK,
                                                 0, NULL,
                                                 (void *)state);
    }
}

/* Public key authentication, client-side.  This super-function handles
   everything related to the public key authentication method. */

void ssh_client_auth_pubkey(SshAuthClientOperation op,
                            const char *user,
                            unsigned int packet_type,
                            SshBuffer *packet_in,
                            unsigned char *session_id,
                            size_t session_id_len,
                            void **state_placeholder,
                            SshAuthClientCompletionProc completion,
                            void *completion_context,
                            void *method_context)
{
  SshClientPubkeyAuth state;
  SshClient client;

  SSH_DEBUG(6, ("auth_pubkey op = %d  user = %s", op, user));

  client = (SshClient)method_context;
  state = *state_placeholder;

  switch (op)
    {
    case SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE:
      /* For now, don't try to do anything in the non-interactive phase.
         However, we should probably later make this try those keys that
         don't need passphrases in this phase.  XXX */
      (*completion)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
      
    case SSH_AUTH_CLIENT_OP_START:
      /* This is the first operation for doing public key authentication.
         We should not have any previous saved state when we come here. */
      assert(*state_placeholder == NULL);

      /* Initialize a context. */
      state = ssh_xmalloc(sizeof(*state));
      memset(state, 0, sizeof(*state));
      state->agent = NULL;
      state->last_tried_candidate = 0;
      state->num_candidates = 0;
      state->candidates = NULL;
      state->completion = completion;
      state->completion_context = completion_context;
      state->state_placeholder = state_placeholder;
      state->user = ssh_xstrdup(user);
      state->client = client;

      /* Assign the state to the placeholder that survives across calls. */
      *state_placeholder = state;

      /* Try to open the authentication agent.  Rest of processing will be
         done in the callback. */
      ssh_agent_open(ssh_client_auth_pubkey_agent_open_complete,
                     (void *)state);
      break;
      
    case SSH_AUTH_CLIENT_OP_CONTINUE:
      /* Got a continuation packet from the server. */
      assert(state != NULL);

      /* Save information in the state. */
      state->completion = completion;
      state->completion_context = completion_context;
      state->state_placeholder = state_placeholder;
      ssh_xfree(state->user);
      state->user = ssh_xstrdup(user);
      state->client = client;
      
      /* Process the received continuation packet. */
      switch (packet_type)
        {
        case SSH_MSG_USERAUTH_FAILURE:
          /* The server is not willing to accept the key.  Move to the next
             candidate, and try authenticating with it. */
        try_again:
          state->last_tried_candidate++;
          ssh_client_auth_pubkey_try_this_candidate(state);
          break;
              
        case SSH_MSG_USERAUTH_PK_OK:
          /* The server is willing to accept this key as authentication. */
          if (ssh_client_auth_pubkey_send_signature(state, user,
                                                session_id, session_id_len,
                                                client->common->random_state))
            {
              /* Reading private part of the key was failed. Move to the
                 next candidate.*/
              goto try_again;
            }
          
          break;

        default:
          /* Unexpected response. */
          ssh_fatal("ssh_client_auth_pubkey: unexpected response packet %d",
                    packet_type);
          /*NOTREACHED*/
        }
      break;

    case SSH_AUTH_CLIENT_OP_ABORT:
      /* Abort the authentication operation immediately. */
      ssh_client_auth_pubkey_free_ctx(state);
      *state_placeholder = NULL;
      break;

      /* something weird is going on.. */
    default:
      ssh_fatal("ssh_client_auth_pubkey: unknown op %d", (int)op);
    }
  return;
}
