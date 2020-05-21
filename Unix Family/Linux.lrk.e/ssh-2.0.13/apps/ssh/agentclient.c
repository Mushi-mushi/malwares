/*

agentclient.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Client-side interface to the SSH authentication agent.

*/

#include "ssh2includes.h"
#include "sshcross.h"
#include "sshencode.h"
#include "sshtcp.h"
#include "sshagent.h"
#include "sshagentint.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshAgentClient"

/* Timeout for agent requests. */
#define SSH_AGENT_TIMEOUT       (30L) /* seconds */

/* In this module, we assume that we never send so big requests that
   SshCrossDown couldn't handle them.  Thus, we don't need can_send
   callbacks.  */

/* Internal status of the agent client. */
typedef enum {
  SSH_AC_IDLE,
  SSH_AC_WAITING_SUCCESS,
  SSH_AC_WAITING_LIST,
  SSH_AC_WAITING_OPERATION_COMPLETE,
  SSH_AC_WAITING_VERSION
} SshAgentClientState;

struct SshAgentRec {
  /* The agent uses a packet format identical to the cross layer protocol.
     Thus, we can use the SshCrossDown and SshCrossUp objects for handling
     the packets.  In the client, we use SshCrossDown. */
  SshCrossDown down;

  /* Agent version, as returned by agent request. */
  unsigned long version;
  
  /* State of the ssh-agent client. */
  SshAgentClientState state;

  /* Is agent from ssh-2.0.{6,7,8,9,10}? */
  Boolean broken_agent;

  /* Various callbacks, depending on the state. */
  SshAgentOpenCallback open_callback;
  SshAgentCompletion completion_callback;
  SshAgentListCallback list_callback;
  SshAgentOpCallback op_callback;
  void *context;
};

/* This is called if a request times out. */

void ssh_agent_timeout(void *context)
{
  SshAgent agent = (SshAgent)context;

  switch (agent->state)
    {
    case SSH_AC_IDLE:
      ssh_debug("ssh_agent_timeout when IDLE???");
      break;
    case SSH_AC_WAITING_SUCCESS:
      if (agent->completion_callback)
        (*agent->completion_callback)(SSH_AGENT_ERROR_TIMEOUT, agent->context);
      break;
    case SSH_AC_WAITING_LIST:
      if (agent->list_callback)
        (*agent->list_callback)(SSH_AGENT_ERROR_TIMEOUT, 0, NULL,
                                agent->context);
      break;
    case SSH_AC_WAITING_OPERATION_COMPLETE:
      if (agent->op_callback)
        (*agent->op_callback)(SSH_AGENT_ERROR_TIMEOUT, NULL, 0,
                              agent->context);
      break;
    case SSH_AC_WAITING_VERSION:
      if (agent->open_callback)
        (*agent->open_callback)(NULL, agent->context);
      ssh_agent_close(agent);
      break;
    default:
      ssh_debug("ssh_agent_timeout: bad state %d", (int)agent->state);
    }
}

/* This is called when a packet is received from the agent. */

void ssh_agent_received_packet(SshCrossPacketType type,
                               const unsigned char *data,
                               size_t len,
                               void *context)
{
  SshAgent agent = (void *)context;
  SshAgentError err;
  SshUInt32 code, temp, num_keys;
  const unsigned char *result;
  size_t result_len, bytes;
  SshAgentKeyInfo keys;
  int i;

  switch ((int)type)
    {
    case 2: /* Version response from old (version 1.x) ssh-agent. */
      ssh_debug("ssh_agent_received_packet: packet number 2 (version response from 1.x agent)");
      agent->version = 1;

      /* We don't support the 1.x agent yet.  Nor will we ever. */
      agent->state = SSH_AC_IDLE;
      if (agent->open_callback)
        (*agent->open_callback)(NULL, agent->context);
      ssh_agent_close(agent);
      return;

    case SSH_AGENT_SUCCESS:
      if (agent->state != SSH_AC_WAITING_SUCCESS)
        {
          ssh_debug("ssh_agent_received_packet: unexpected %d", (int)type);
          return;
        }
      if (len != 0)
        ssh_debug("ssh_agent_received_packet: SUCCESS bad data");
      ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
      agent->state = SSH_AC_IDLE;
      if (agent->completion_callback)
        (*agent->completion_callback)(SSH_AGENT_ERROR_OK, agent->context);
      break;
      
    case SSH_AGENT_FAILURE:
      if (agent->state == SSH_AC_WAITING_VERSION)
        {
          /* This may happen, if we have agent from versions
             ssh-2.0.{7-10} and our client is newer.  We now send
             the version request again without identifying our own
             version and leaving the state waiting for version 
             response. */
          agent->broken_agent = TRUE;
          ssh_cross_down_send_encode(agent->down,
                                (SshCrossPacketType)SSH_AGENT_REQUEST_VERSION,
                                 SSH_FORMAT_END);
          return;
        }
      if (agent->state != SSH_AC_WAITING_SUCCESS &&
          agent->state != SSH_AC_WAITING_OPERATION_COMPLETE)
        {
          ssh_debug("ssh_agent_received_packet: unexpected %d", (int)type);
          return;
        }
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &code,
                           SSH_FORMAT_END) != len)
        {
          ssh_debug("ssh_agent_received_packet: FAILURE bad data");
          err = SSH_AGENT_ERROR_FAILURE;
        }
      else
        err = (SshAgentError)code;

      ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
      if (agent->state == SSH_AC_WAITING_SUCCESS)
        {
          agent->state = SSH_AC_IDLE;
          if (agent->completion_callback)
            (*agent->completion_callback)(err, agent->context);
        }
      else
        {
          agent->state = SSH_AC_IDLE;
          if (agent->op_callback)
            (*agent->op_callback)(err, NULL, 0, agent->context);
        }
      break;

    case SSH_AGENT_VERSION_RESPONSE:
      if (agent->state != SSH_AC_WAITING_VERSION)
        {
          ssh_debug("ssh_agent_received_packet: unexpected %d", (int)type);
          return;
        }
      ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
      if (ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32, &temp,
                               SSH_FORMAT_END) != len)
        {
          ssh_debug("ssh_agent_received_packet: VERSION_RESPONSE bad data");
          return;
        }
      agent->version = temp;
      agent->state = SSH_AC_IDLE;
      if (agent->open_callback)
        (*agent->open_callback)(agent, agent->context);
      break;
      
    case SSH_AGENT_KEY_LIST:
      if (agent->state != SSH_AC_WAITING_LIST)
        {
          ssh_debug("ssh_agent_received_packet: unexpected %d", (int)type);
          return;
        }
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32, &num_keys,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          ssh_debug("ssh_agent_received_packet: KEY_LIST bad data");
        list_fail:
          if (agent->list_callback)
            (*agent->list_callback)(SSH_AGENT_ERROR_FAILURE, 0, NULL,
                                    agent->context);
          return;
        }

      keys = ssh_xmalloc(num_keys * sizeof(keys[0]));
      data += bytes;
      len -= bytes;
      for (i = 0; i < num_keys; i++)
        {
          bytes = ssh_decode_array(data, len,
                                   SSH_FORMAT_UINT32_STR_NOCOPY,
                                     &keys[i].certs, &keys[i].certs_len,
                                   SSH_FORMAT_UINT32_STR,
                                     &keys[i].description, NULL,
                                   SSH_FORMAT_END);
          if (bytes == 0)
            {
              ssh_debug("ssh_agent_received_packet: bad data key %d", i);
              for (i--; i >= 0; i--)
                ssh_xfree(keys[i].description);
              ssh_xfree(keys);
              goto list_fail;
            }
          data += bytes;
          len -= bytes;
        }
      if (len != 0)
        {
          ssh_debug("ssh_agent_received_packet: data left after keys");
          for (i--; i >= 0; i--)
            ssh_xfree(keys[i].description);
          ssh_xfree(keys);
          goto list_fail;
        }
      ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
      agent->state = SSH_AC_IDLE;
      if (agent->list_callback)
        (*agent->list_callback)(SSH_AGENT_ERROR_OK, (unsigned int)num_keys,
                                keys, agent->context);
      for (i = 0; i < num_keys; i++)
        ssh_xfree(keys[i].description);
      ssh_xfree(keys);
      break;
      
    case SSH_AGENT_OPERATION_COMPLETE:
      if (agent->state != SSH_AC_WAITING_OPERATION_COMPLETE)
        {
          ssh_debug("ssh_agent_received_packet: unexpected OP_COMPLETE");
          return;
        }
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &result, &result_len,
                           SSH_FORMAT_END) != len)
        {
          ssh_debug("ssh_agent_received_packet: OP_COMPLETE bad data");
          return;
        }
      ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
      agent->state = SSH_AC_IDLE;
      if (agent->op_callback)
        (*agent->op_callback)(SSH_AGENT_ERROR_OK, result, result_len,
                              agent->context);
      break;

    default:
      ssh_debug("ssh_agent_received_packet: received unknown packet %d",
                (int)type);
    }
}

/* This is called when EOF is received from the agent. */

void ssh_agent_received_eof(void *context)
{
  SshAgent agent = (SshAgent)context;

  ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
  
  switch (agent->state)
    {
    case SSH_AC_IDLE:
      break;
    case SSH_AC_WAITING_SUCCESS:
      if (agent->completion_callback)
        (*agent->completion_callback)(SSH_AGENT_ERROR_FAILURE, agent->context);
      break;
    case SSH_AC_WAITING_LIST:
      if (agent->list_callback)
        (*agent->list_callback)(SSH_AGENT_ERROR_FAILURE, 0, NULL,
                                agent->context);
      break;
    case SSH_AC_WAITING_OPERATION_COMPLETE:
      if (agent->op_callback)
        (*agent->op_callback)(SSH_AGENT_ERROR_FAILURE, NULL, 0,
                              agent->context);
      break;
    case SSH_AC_WAITING_VERSION:
      if (agent->open_callback)
        (*agent->open_callback)(NULL, agent->context);
      ssh_agent_close(agent);
      break;
    default:
      ssh_debug("ssh_agent_received_eof: bad state %d", (int)agent->state);
    }
}

/* Checks whether the authentication agent is present.  Returns TRUE if yes.
   This is not completely reliable; this may sometimes return TRUE even if
   the agent is not actually present (in which case ssh_agent_open
   will fail). */

Boolean ssh_agent_present()
{
  return ((getenv(SSH_AGENT_VAR) != NULL) ||
          (getenv(SSH_AA_VAR) != NULL));
}

typedef struct SshAgentOpenContextRec {
  SshAgentOpenCallback callback;
  void *context;
} *SshAgentOpenContext;

/* Called when connecting to the agent socket completes. */

void ssh_agent_open_complete(SshStream stream, void *context)
{
  SshAgentOpenContext c = (SshAgentOpenContext)context;
  SshAgent agent;

  /* If failed to connect, simply return. */
  if (stream == NULL)
    {
      (*c->callback)(NULL, c->context);
      ssh_xfree(c);
      return;
    }

  /* Initialize the agent connection object. */
  agent = ssh_xcalloc(1, sizeof(*agent));
  agent->down = ssh_cross_down_create(stream,
                                      ssh_agent_received_packet,
                                      ssh_agent_received_eof,
                                      NULL,
                                      (void *)agent);
  ssh_cross_down_can_receive(agent->down, TRUE);

  /* Prepare to send version request. */
  agent->state = SSH_AC_WAITING_VERSION;
  agent->open_callback = c->callback;
  agent->context = c->context;
  ssh_xfree(c);
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);

  /* Send a version request message. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_REQUEST_VERSION,
                             SSH_FORMAT_UINT32_STR,
                             SSH2_VERSION_STRING, strlen(SSH2_VERSION_STRING),
                             SSH_FORMAT_END);

  /* The callback will be called when a version number has been received
     or the request times out. */
}

/* Opens a connection to the authentication agent.  Returns NULL on error,
   or a pointer to a connection handle otherwise. */

void ssh_agent_open(SshAgentOpenCallback callback, void *context)
{
  SshAgentOpenContext c;

  /* Prepare the context structure. */
  c = ssh_xmalloc(sizeof(*c));
  c->callback = callback;
  c->context = context;

  /* Connect to the agent socket. */
  ssh_agenti_connect(ssh_agent_open_complete, FALSE, (void *)c);
}

/* Closes the connection to the authentication agent.  If a command is
   active, it is terminated and its callback will never be called. */

void ssh_agent_close(SshAgent agent)
{
  ssh_cross_down_destroy(agent->down);
  ssh_cancel_timeouts(ssh_agent_timeout, (void *)agent);
  memset(agent, 'F', sizeof(*agent));
  ssh_xfree(agent);
}

void ssh_agent_init_key_attrs(SshAgentKeyAttrs attrs)
{
  attrs->status = 0;
  attrs->use_limit = 0xffffffff;
  attrs->path_len_limit = 0xffffffff;
  attrs->path_constraint = NULL;
  attrs->timeout_time = (SshTime) 0;
  attrs->compat_allowed = TRUE; 
}

void ssh_agent_add_generic(SshAgent agent,
                           SshPrivateKey key,
                           const unsigned char *certs,
                           size_t certs_len,
                           const char *description,
                           SshAgentKeyAttrs attrs,
                           SshAgentCompletion callback,
                           void *context)
{
  unsigned char *blob;
  size_t blob_len;
  SshRandomState dummy_random_state;
  SshBuffer buffer;

  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_add: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, context);
      return;
    }
  
  /* Allocate a dummy random state.  This is needed to export a private
     key.  However, we export without encryption, so it doesn't matter
     whether the random state is initialized.  For that reason, we don't
     require it to be externally supplied nor try to add any entropy. */
  if (key)
    {
      dummy_random_state = ssh_random_allocate();
      if (ssh_private_key_export(key, "none", (unsigned char *)"", 
                                 0, dummy_random_state, &blob,
                                 &blob_len) != SSH_CRYPTO_OK)
        {
          ssh_random_free(dummy_random_state);
          ssh_debug("ssh_agent_add: export failed");
          if (callback)
            (*callback)(SSH_AGENT_FAILURE, context);
          return;
        }
      /* Free the dummy random state.  It is no longer needed. */
      ssh_random_free(dummy_random_state);
    }
  else
    {
      blob = NULL;
      blob_len = 0;
    }

  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_SUCCESS;
  agent->completion_callback = callback;
  agent->context = context;
  
  /* Send the request. */
  if (attrs == NULL)
    {
      ssh_cross_down_send_encode(agent->down,
                                 (SshCrossPacketType)SSH_AGENT_ADD_KEY,
                                 SSH_FORMAT_UINT32_STR, blob, blob_len,
                                 SSH_FORMAT_UINT32_STR, certs, certs_len,
                                 SSH_FORMAT_UINT32_STR,
                                 description, strlen(description),
                                 SSH_FORMAT_END);
    }
  else
    {
      ssh_buffer_init(&buffer);
      if (attrs->timeout_time != 0)
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_CHAR, 
                            (unsigned int)SSH_AGENT_CONSTRAINT_TIMEOUT,
                            SSH_FORMAT_UINT32, (SshUInt32) attrs->timeout_time,
                            SSH_FORMAT_END);
      if (attrs->use_limit != 0xffffffff)
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_CHAR, 
                            (unsigned int)SSH_AGENT_CONSTRAINT_USE_LIMIT,
                            SSH_FORMAT_UINT32, attrs->use_limit,
                            SSH_FORMAT_END);
      if (attrs->path_len_limit != 0xffffffff)
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_CHAR, 
                           (unsigned int)SSH_AGENT_CONSTRAINT_FORWARDING_STEPS,
                            SSH_FORMAT_UINT32, attrs->path_len_limit,
                            SSH_FORMAT_END);
      if (attrs->path_constraint != NULL)
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_CHAR, 
                            (unsigned int)SSH_AGENT_CONSTRAINT_FORWARDING_PATH,
                            SSH_FORMAT_UINT32_STR, 
                            attrs->path_constraint, 
                            strlen(attrs->path_constraint),
                            SSH_FORMAT_END);
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_CHAR, 
                        (unsigned int)SSH_AGENT_CONSTRAINT_COMPAT,
                        SSH_FORMAT_BOOLEAN, attrs->compat_allowed,
                        SSH_FORMAT_END);
      ssh_cross_down_send_encode(agent->down,
                                 (SshCrossPacketType)SSH_AGENT_ADD_KEY,
                                 SSH_FORMAT_UINT32_STR, blob, blob_len,
                                 SSH_FORMAT_UINT32_STR, certs, certs_len,
                                 SSH_FORMAT_UINT32_STR,
                                 description, strlen(description),
                                 SSH_FORMAT_DATA,
                                 ssh_buffer_ptr(&buffer),
                                 ssh_buffer_len(&buffer),
                                 SSH_FORMAT_END);
      ssh_buffer_uninit(&buffer);
    }

  /* Free data that is no longer needed. */
  ssh_xfree(blob);
}

/* Adds the given private key to the agent. */

void ssh_agent_add(SshAgent agent,
                   SshPrivateKey key,
                   const unsigned char *certs,
                   size_t certs_len,
                   const char *description,
                   SshAgentCompletion callback,
                   void *context)
{
  ssh_agent_add_generic(agent, key, certs, certs_len, description,
                        NULL, callback, context);
}

/* Adds the given private key to the agent with attributes. */

void ssh_agent_add_with_attrs(SshAgent agent,
                              SshPrivateKey key,
                              const unsigned char *certs,
                              size_t certs_len,
                              const char *description,
                              SshUInt32 path_len_limit, 
                              char *path_constraint,
                              SshUInt32 use_limit, 
                              Boolean compat_forbidden, 
                              SshTime timeout_time,
                              SshAgentCompletion callback,
                              void *context)
{
  struct SshAgentKeyAttrsRec attrs;
  
  if (agent->broken_agent)
    {
      ssh_debug("ssh_agent_add: remote agent broken");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_FAILURE, context);
      return;
    }
  attrs.path_len_limit = path_len_limit;
  attrs.compat_allowed = !compat_forbidden;
  attrs.timeout_time = timeout_time;
  attrs.use_limit = use_limit;
  attrs.path_constraint = (path_constraint ? 
                           ssh_xstrdup(path_constraint) : NULL);
  ssh_agent_add_generic(agent, key, certs, certs_len, description,
                        &attrs, callback, context);
}

/* Deletes the given key from the agent. */

void ssh_agent_delete_all(SshAgent agent, SshAgentCompletion callback,
                          void *context)
{
  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_delete_all: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, context);
      return;
    }

  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_SUCCESS;
  agent->completion_callback = callback;
  agent->context = context;

  /* Send the request. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_DELETE_ALL_KEYS,
                             SSH_FORMAT_END);
}

/* Deletes the given key from the agent. */
void ssh_agent_delete(SshAgent agent, 
                      const unsigned char *certs, size_t certs_len,
                      const char *description,
                      SshAgentCompletion callback, void *context)
{
  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_delete: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, context);
      return;
    }

  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_SUCCESS;
  agent->completion_callback = callback;
  agent->context = context;

  /* Send the request. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_DELETE_KEY,
                             SSH_FORMAT_UINT32_STR, certs, certs_len,
                             SSH_FORMAT_UINT32_STR, description, 
                             (description ? strlen(description) : 0),
                             SSH_FORMAT_END);
}

/* Returns the public keys for all private keys in possession of the agent.
   Only a single operation may be in progress on the connection at any
   one time. */

void ssh_agent_list(SshAgent agent, SshAgentListCallback callback,
                    void *context)
{
  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_list: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, 0, NULL, context);
      return;
    }
  
  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_LIST;
  agent->list_callback = callback;
  agent->context = context;

  /* Send the request. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_LIST_KEYS,
                             SSH_FORMAT_END);
}

/* Performs a private-key operation using the agent.  Calls the given
   callback when a reply has been received or a timeout occurs.
   Only a single operation may be in progress on the connection at any
   one time. */

void ssh_agent_op(SshAgent agent, SshAgentOp op,
                  const unsigned char *certs, size_t certs_len,
                  const unsigned char *data, size_t len,
                  SshAgentOpCallback callback, void *context)
{
  const char *name;

  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_op: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, NULL, 0, context);
      return;
    }

  switch (op)
    {
    case SSH_AGENT_SIGN:
      name = "sign";
      break;
    case SSH_AGENT_HASH_AND_SIGN:
      name = "hash-and-sign";
      break;
    case SSH_AGENT_DECRYPT:
      name = "decrypt";
      break;
    case SSH_AGENT_SSH1_CHALLENGE_RESPONSE:
      name = "ssh1-challenge-response";
      break;
    default:
      (*callback)(SSH_AGENT_FAILURE, NULL, 0, context);
      return;
    }

  /* Prepare to send request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_OPERATION_COMPLETE;
  agent->op_callback = callback;
  agent->context = context;

  /* Send the request packet. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_PRIVATE_KEY_OP,
                             SSH_FORMAT_UINT32_STR, name, strlen(name),
                             SSH_FORMAT_UINT32_STR, certs, certs_len,
                             SSH_FORMAT_UINT32_STR, data, len,
                             SSH_FORMAT_END);
}


/* Locks the agent with given password */
void ssh_agent_lock(SshAgent agent, const char *password,
                    SshAgentCompletion callback, void *context)
{
  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_lock: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, context);
      return;
    }

  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_SUCCESS;
  agent->completion_callback = callback;
  agent->context = context;

  /* Send the request. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_LOCK,
                             SSH_FORMAT_UINT32_STR, 
                             password, (password ? strlen(password) : 0),
                             SSH_FORMAT_END);
}

/* Attempts to unlock the agent with given password */
void ssh_agent_unlock(SshAgent agent, const char *password,
                      SshAgentCompletion callback, void *context)
{
  if (agent->state != SSH_AC_IDLE)
    {
      ssh_debug("ssh_agent_unlock: busy");
      if (callback)
        (*callback)(SSH_AGENT_ERROR_BUSY, context);
      return;
    }

  /* Prepare to send the request. */
  ssh_register_timeout(SSH_AGENT_TIMEOUT, 0L,
                       ssh_agent_timeout, (void *)agent);
  agent->state = SSH_AC_WAITING_SUCCESS;
  agent->completion_callback = callback;
  agent->context = context;

  /* Send the request. */
  ssh_cross_down_send_encode(agent->down,
                             (SshCrossPacketType)SSH_AGENT_UNLOCK,
                             SSH_FORMAT_UINT32_STR, 
                             password, (password ? strlen(password) : 0),
                             SSH_FORMAT_END);
}
