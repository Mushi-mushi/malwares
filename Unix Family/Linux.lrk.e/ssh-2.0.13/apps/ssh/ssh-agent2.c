/*

ssh-agent.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

The ssh authentication agent.

*/

#include "ssh2includes.h"
#include "sshcipherlist.h"
#include "sshcross.h"
#include "sshencode.h"
#include "sshtcp.h"
#include "sshmatch.h"
#include "sshtimeouts.h"
#include "sshagent.h"
#include "sshagentint.h"
#include "sshuser.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshgetopt.h"
#include "ssh2pubkeyencode.h"
#include "sshmp.h" /* was "gmp.h" */

#define SSH_DEBUG_MODULE "SshAgent"

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

#define SSH_AGENT_CHECK_PARENT_INTERVAL         10
#define SSH_AGENT_CHECK_EXPIRED_KEYS_INTERVAL   60

typedef struct SshAgentImplRec *SshAgentImpl;

typedef struct SshAgentConnectionRec {
  struct SshAgentConnectionRec *next;
  SshAgentImpl agent;
  SshCrossDown down;
  char *forwarding_path;
  SshUInt32 forwarding_path_len;
} *SshAgentConnection;

typedef struct SshAgentKeyRec {
  struct SshAgentKeyRec *next;
  unsigned char *certs;
  size_t certs_len;
  SshPrivateKey private_key;
  char *description;
  struct SshAgentKeyAttrsRec attr;

#ifdef WITH_SSH_AGENT1_COMPAT
  Boolean ssh1_key_available;
#endif /* WITH_SSH_AGENT1_COMPAT */
} *SshAgentKey;

#ifdef WITH_SSH_AGENT1_COMPAT
typedef struct SshAgentSsh1KeyRec {
  struct SshAgentSsh1KeyRec *next;
  SshInt n;
  SshInt e;
  SshInt d;
  char *description;
} *SshAgentSsh1Key;
#endif /* WITH_SSH_AGENT1_COMPAT */

struct SshAgentImplRec {
  SshAgentConnection connections;
  SshLocalListener listener;
  SshAgentKey keys;
  char *socket_name;
  char *socket_dir_name;
  char *lock_password;
  SshRandomState random_state;
#ifdef WITH_SSH_AGENT1_COMPAT
  /* Is `-1' flag on? */
  Boolean ssh1_compat;
  SshAgentSsh1Key ssh1_keys;
#endif /* WITH_SSH_AGENT1_COMPAT */
};

const char *av0; /* Program name */

/* Formats and sends a packet down the connection.  The variable argument list
   specifies the contents of the packet as specified in sshencode.h. */
void ssh_agenti_send(SshAgentConnection conn, unsigned int packet_type, ...);

/* Formats and sends a SSH_AGENT_FAILURE packet. */
void ssh_agenti_send_error(SshAgentConnection conn, unsigned int err);

/* Looks up a key with the given certs.  The certs are required to match
   bitwise exactly.  This returns NULL if no such key is found. */
SshAgentKey ssh_agenti_find_key(SshAgentImpl agent,
                                const unsigned char *certs, 
                                size_t certs_len,
                                Boolean extended_search);

/* Generate a name string from public key */
char *ssh_agenti_generate_name_from_public_key(char *name, SshPublicKey key);

/* Allocate a new empty key structure. */
SshAgentKey ssh_agenti_key_allocate(void);

/* Adds the given private key to be managed by the agent.  `private_blob',
   `public_blob', and `description' must have been allocated by ssh_xmalloc;
   this will free them when no longer needed.  This returns TRUE on
   SUCCESS, FALSE on failure. */
Boolean ssh_agenti_add_key(SshAgentImpl agent,
                           unsigned char *private_blob,
                           size_t private_len,
                           SshPrivateKey private_key,
                           unsigned char *public_blob,
                           size_t public_len,
                           char *description,
                           SshAgentKeyAttrs attrs,
                           Boolean ssh1_key_available);

/* Deletes all keys from the agent. */
void ssh_agenti_delete_keys(SshAgentImpl agent);

/* Delete a key with given certs */
Boolean ssh_agenti_delete_key(SshAgentImpl agent,
                              unsigned char *certs,
                              size_t certs_len);

/* Lists all keys in possession of the agent.  This sends the response
   message to the client. */
void ssh_agenti_list_keys(SshAgentConnection conn);

/* Performs a private-key operation using the agent.  `op_name'
   identifies the operation to perform, and `public_key' the key.  (Both
   allocated by ssh_xmalloc, and are freed by this function when no longer
   needed.)  This will send a response packet when the operation is
   complete (which may be either during this call or some time later). */
void ssh_agenti_private_key_op(SshAgentConnection conn, char *op_name,
                               const unsigned char *public_blob,
                               size_t public_len,
                               const unsigned char *data, size_t len);

/* This function is called whenever the agent receives a packet from a client.
   This will process the request, and eventually send a response. */
void ssh_agenti_received_packet(SshCrossPacketType type,
                                const unsigned char *data, size_t len,
                                void *context);

/* This fuction is called when eof is received from agent connection. */
void ssh_agenti_received_eof(void *context);

/* Processes a new incoming connection to the agent.  This is called when
   a new client connects. */
void ssh_agenti_connection(SshStream stream, void *context);

/* Creates the authentication agent and starts listening for connections. */
SshAgentImpl ssh_agenti_create(char **path_return);

/* This is called periodically by a timeout, and checks whether the parent
   process is still alive. */
void ssh_agenti_check_parent(void *context);

/* This is called periodically by a timeout in order to delete keys
   that are expored.  This timeout can also be called from private
   key operations in order to avoid using the expired key. */
void ssh_agenti_check_timeout_keys(void *context);

/* Return TRUE if agent forwarding path is too long for given key
   or if the key has expired. */
Boolean ssh_agenti_invalid_key(SshAgentConnection conn, 
                               SshAgentKeyAttrs attrs);

#ifdef WITH_SSH_AGENT1_COMPAT

/* Make ssh1 style (length in two bytes) encoding of long integer */
void ssh_agenti_ssh1_encode_mp(SshBuffer *buffer, SshInt *n);

/* Decode ssh1 style encoded long integer */
Boolean ssh_agenti_ssh1_decode_mp(SshBuffer *buffer, SshInt *n);

/* Reply to the list query from ssh-agent1 */
void ssh_agenti_ssh1_list_keys(SshAgentConnection conn);

/* Reply to the challenge from ssh-agent1 */
void ssh_agenti_ssh1_challenge(SshAgentConnection conn, 
                               const unsigned char *data, 
                               size_t len);

/* Add a private key send by ssh-agent1 */
void ssh_agenti_ssh1_add_key(SshAgentConnection conn, 
                             const unsigned char *data, 
                             size_t len);

/* Remove a private key by request of ssh-agent1 */
void ssh_agenti_ssh1_remove_key(SshAgentConnection conn, 
                                const unsigned char *data, 
                                size_t len);

/* Remove all keys by request of ssh-agent1 */
void ssh_agenti_ssh1_remove_all_keys(SshAgentConnection conn);

/* Handler for packets sent by ssh-agent1 */
void ssh_agenti_handle_ssh1_packet(SshAgentConnection conn, 
                                   SshCrossPacketType type,
                                   const unsigned char *data, 
                                   size_t len);

/* Find ssh1 key with the given public part */
SshAgentSsh1Key ssh_agenti_ssh1key_find(SshAgentImpl agent,
                                         SshInt *n, 
                                         SshInt *e);

/* Adds the given ssh1 private key to be managed by the agent. */
Boolean ssh_agenti_ssh1key_add(SshAgentImpl agent,
                               SshInt *n, 
                               SshInt *e,
                               SshInt *d,
                               char *description);

/* Delete a ssh1 key with given public key */
Boolean ssh_agenti_ssh1key_delete(SshAgentImpl agent,
                                   SshInt *n, 
                                   SshInt *e);

/* Delete all ssh1 keys */
void ssh_agenti_ssh1key_delete_all(SshAgentImpl agent);

#endif /* WITH_SSH_AGENT1_COMPAT */

/* Note: we don't process can_send callbacks.  This assumes that we always
   send small enough packets that they fit in buffers. */

/* Formats and sends a packet down the connection.  The variable argument list
   specifies the contents of the packet as specified in sshencode.h. */
void ssh_agenti_send(SshAgentConnection conn, unsigned int packet_type, ...)
{
  va_list ap;

  va_start(ap, packet_type);
  ssh_cross_down_send_encode_va(conn->down, (SshCrossPacketType)packet_type,
                                ap);
  va_end(ap);
}

/* Formats and sends a SSH_AGENT_FAILURE packet. */
void ssh_agenti_send_error(SshAgentConnection conn, unsigned int err)
{
  ssh_agenti_send(conn, SSH_AGENT_FAILURE,
                  SSH_FORMAT_UINT32, (SshUInt32) err,
                  SSH_FORMAT_END);
}

/* Looks up a key with the given certs.  The certs are required to match
   bitwise exactly.  This returns NULL if no such key is found. */
SshAgentKey ssh_agenti_find_key(SshAgentImpl agent,
                                const unsigned char *certs, 
                                size_t certs_len,
                                Boolean extended_search) /*ARGSUSED*/
{
  SshAgentKey key;

  for (key = agent->keys; key; key = key->next)
    if (key->certs_len == certs_len &&
        memcmp(key->certs, certs, certs_len) == 0)
      return key;
  return  NULL;
}

/* Generate a name string from public key */
char *ssh_agenti_generate_name_from_public_key(char *name, SshPublicKey key)
{
  unsigned char *kb;
  size_t bl;
  char *r;

  bl = ssh_encode_pubkeyblob(key, &kb);
  r = ssh_generate_name_from_blob(name, kb, bl);
  ssh_xfree(kb);
  return r;
}

size_t ssh_split_comma_list(const char *str, char ***arr)
{
  
  char *s, *hlp1, *hlp2, **a;
  size_t n, x;
  
  s = ssh_xstrdup(str);
  n = 1;
  /* Count comma characters */
  for (hlp1 = s; *hlp1; hlp1++)
    if (*hlp1 == ',')
      n++;
  /* Allocate for pointers + NULL pointer */
  a = ssh_xcalloc(n + 1, sizeof (char *));
  x = 0;
  /* Traverse the list. */
  for (hlp1 = hlp2 = s; /*NOTHING*/; hlp1++)
    {
      SSH_ASSERT(x < n);
      if (*hlp1 == '\000')
        {
          a[x] = ssh_xstrdup(hlp2);
          break;
        }
      else if (*hlp1 == ',')
        {
          *hlp1 = '\000';
          a[x++] = ssh_xstrdup(hlp2);
          hlp2 = hlp1;
          hlp2++;
        }
    }
  /* Assign or free. */
  if (arr)
    {
      *arr = a;
    }
  else
    {
      for (x = 0; x < n; x++)
        ssh_xfree(a[x]);
      ssh_xfree(a);
    }
  return n;
}

Boolean ssh_agent_path_match(const char *rule, const char *path)
{
  char **r, **p;
  size_t nr, np, x, y;

  /* Empty rule allows everything. */
  if ((rule == NULL) || (*rule == '\000'))
    {
      SSH_DEBUG(7, ("everything matches to empty rule"));
      return TRUE;
    }
  /* Empty path allows everything */
  if ((path == NULL) || (*path == '\000'))
    {
      SSH_DEBUG(7, ("empty path matches to every rule"));
      return TRUE;
    }
  nr = ssh_split_comma_list(rule, &r);
  np = ssh_split_comma_list(path, &p);
  for (x = 0; x < np; x++)
    {
      for (y = 0; y < nr; y++)
        {
          if (ssh_match_pattern(p[x], r[y]))
            break;
        }
      if (y >= nr)
        break;
    }
  for (x = 0; x < np; x++)
    ssh_xfree(p[y]);
  ssh_xfree(p);
  for (x = 0; x < nr; x++)
    ssh_xfree(r[y]);
  ssh_xfree(r);
  return (y < nr);
}

/* Allocate a new empty key structure. */
SshAgentKey ssh_agenti_key_allocate()
{
  SshAgentKey key;

  key = ssh_xcalloc(1, sizeof (*key));
  ssh_agent_init_key_attrs(&(key->attr));
  return key;
}

/* Adds the given private key to be managed by the agent.  `private_blob',
   `public_blob', and `description' must have been allocated by ssh_xmalloc;
   this will free them when no longer needed.  This returns TRUE on
   SUCCESS, FALSE on failure. */
Boolean ssh_agenti_add_key(SshAgentImpl agent,
                           unsigned char *private_blob,
                           size_t private_len,
                           SshPrivateKey private_key,
                           unsigned char *public_blob,
                           size_t public_len,
                           char *description,
                           SshAgentKeyAttrs attrs,
                           Boolean ssh1_key_available)
{
  SshAgentKey key;
  unsigned char *certs_copy;

  /* Check if this is an URL.  Can't process them. */
  if ((private_len == 0) && (public_len == 0))
    {
      ssh_xfree(private_blob);
      ssh_xfree(public_blob);
      if (private_key)
        ssh_private_key_free(private_key);
      ssh_xfree(description);
      return FALSE;
    }

  /* Check if we already have the key. */
  key = ssh_agenti_find_key(agent, public_blob, public_len, FALSE);
  if (key != NULL)
    {
      SSH_DEBUG(5, ("key found, removing it to allow change of attributes"));
      certs_copy = ssh_xmemdup(public_blob, public_len);
      ssh_agenti_delete_key(agent, certs_copy, public_len);
    }

  key = ssh_agenti_key_allocate();
  if (attrs)
    key->attr = *attrs;
  else
    ssh_agent_init_key_attrs(&(key->attr));

  if (private_key == NULL)
    {
      /* Import private key. */
      if (ssh_private_key_import(private_blob, private_len, NULL, 0,
                                 &key->private_key) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(3, ("private key import failed"));
          ssh_xfree(key);
          ssh_xfree(private_blob);
          ssh_xfree(public_blob);
          ssh_xfree(description);
          return FALSE;
        }
    }
  else
    {
      key->private_key = private_key;
    }
  ssh_xfree(private_blob);

  /* Fill in the remaining fields and add to the list of keys. */
  key->certs = public_blob;
  key->certs_len = public_len;
  key->description = description;
  key->next = agent->keys;
  agent->keys = key;
#ifdef WITH_SSH_AGENT1_COMPAT
  key->ssh1_key_available = ssh1_key_available;
#endif /* WITH_SSH_AGENT1_COMPAT */
  return TRUE;
}

/* Deletes all keys from the agent. */
void ssh_agenti_delete_keys(SshAgentImpl agent)
{
  SshAgentKey key;

  while (agent->keys != NULL)
    {
      key = agent->keys;
      agent->keys = key->next;

      ssh_xfree(key->certs);
      ssh_xfree(key->description);
      ssh_private_key_free(key->private_key);
      memset(key, 'F', sizeof(*key));
      ssh_xfree(key);
    }
#ifdef WITH_SSH_AGENT1_COMPAT
  /* This deletes also all possible ssh1 keys. */
  ssh_agenti_ssh1key_delete_all(agent);
#endif /* WITH_SSH_AGENT1_COMPAT */
}

/* Delete a key with given certs */
Boolean ssh_agenti_delete_key(SshAgentImpl agent,
                              unsigned char *certs,
                              size_t certs_len)
{
  SshAgentKey key;
  SshAgentKey tmpkey = NULL;
  SshAgentKey newkey = NULL;
  Boolean success = FALSE;

  /* Remove the key with given certs */
  for (tmpkey = agent->keys; tmpkey; /*NOTHING*/)
    {
      key = tmpkey;
      tmpkey = key->next;
      if ((key->certs_len != certs_len) ||
          (memcmp(key->certs, certs, certs_len) != 0))
        {
          key->next = newkey;
          newkey = key;
        }
      else
        {
          ssh_xfree(key->certs);
          ssh_xfree(key->description);
          ssh_private_key_free(key->private_key);
          memset(key, 'F', sizeof(*key));
          ssh_xfree(key);
          success = TRUE;
        }
    }
  ssh_xfree(certs);
  agent->keys = newkey;
  newkey = NULL;

  /* Turn the list over to restore original order */
  for (tmpkey = agent->keys; tmpkey; /*NOTHING*/)
    {
      key = tmpkey;
      tmpkey = key->next;
      key->next = newkey;
      newkey = key;
    }
  agent->keys = newkey;

  return success;
}


/* Lists all keys in possession of the agent.  This sends the response
   message to the client. */
void ssh_agenti_list_keys(SshAgentConnection conn)
{
  SshAgentKey key;
  SshUInt32 num_keys;
  SshBuffer buffer;

  if (conn->agent->lock_password)
    {
      ssh_agenti_send(conn, SSH_AGENT_KEY_LIST,
                      SSH_FORMAT_UINT32, 
                      (SshUInt32)0,
                      SSH_FORMAT_END);
      return;
    }

  /* Build the list of keys first, counting the keys at the same time. */
  num_keys = 0;
  ssh_buffer_init(&buffer);

  for (key = conn->agent->keys; key; key = key->next)
    {
      if (! ssh_agenti_invalid_key(conn, &(key->attr)))
        {
          num_keys++;
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_UINT32_STR, 
                            key->certs, key->certs_len,
                            SSH_FORMAT_UINT32_STR,
                            key->description, strlen(key->description),
                            SSH_FORMAT_END);
        }
    }

  /* Construct and send the final response packet. */
  ssh_agenti_send(conn, SSH_AGENT_KEY_LIST,
                  SSH_FORMAT_UINT32, num_keys,
                  SSH_FORMAT_DATA, ssh_buffer_ptr(&buffer), 
                  ssh_buffer_len(&buffer),
                  SSH_FORMAT_END);
  ssh_buffer_uninit(&buffer);
}

/* Performs a private-key operation using the agent.  `op_name'
   identifies the operation to perform, and `public_key' the key.  (Both
   allocated by ssh_xmalloc, and are freed by this function when no longer
   needed.)  This will send a response packet when the operation is
   complete (which may be either during this call or some time later). */
void ssh_agenti_private_key_op(SshAgentConnection conn, char *op_name,
                               const unsigned char *public_blob,
                               size_t public_len,
                               const unsigned char *data, size_t len)
{
  SshAgentKey key;
  const unsigned char *arg;
  size_t arg_len;
  unsigned char *outputbuf;
  size_t outputlen;
  SshPrivateKey privkey;

  SSH_DEBUG(7, ("op=%s", op_name));
  key = ssh_agenti_find_key(conn->agent, public_blob, public_len, TRUE);
  if (key == NULL)
    {
      SSH_DEBUG(5, ("key not found"));
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_KEY_NOT_FOUND);
      return;
    }
  else if (ssh_agenti_invalid_key(conn, &(key->attr)))
    {
      SSH_DEBUG(5, ("key not available because of restriction"));
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_KEY_NOT_FOUND);
      return;
    }
  else
    {
      privkey = key->private_key;
    }

  if (strcmp(op_name, "sign") == 0)
    {
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("sign: bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          goto cleanup_and_return;
        }
      outputlen = ssh_private_key_max_signature_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_sign_digest(privkey, arg, arg_len,
                                      outputbuf, outputlen,
                                      &outputlen, conn->agent->random_state) !=
          SSH_CRYPTO_OK)
        {
          SSH_DEBUG(6, ("sign failed"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
          goto cleanup_and_return;
        }
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
                      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
                      SSH_FORMAT_END);
    }
  else if (strcmp(op_name, "hash-and-sign") == 0)
    {
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("hash-and-sign: bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          goto cleanup_and_return;
        }
      outputlen = ssh_private_key_max_signature_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_sign(privkey, arg, arg_len, outputbuf, outputlen,
                               &outputlen, conn->agent->random_state) !=
          SSH_CRYPTO_OK)
        {
          SSH_DEBUG(6, ("hash-and-sign failed"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
          goto cleanup_and_return;
        }
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
                      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
                      SSH_FORMAT_END);
    }
  else if (strcmp(op_name, "decrypt") == 0)
    {
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("decrypt: bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          goto cleanup_and_return;
        }
      outputlen = ssh_private_key_max_decrypt_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_decrypt(privkey, arg, arg_len,
                                  outputbuf, outputlen,
                                  &outputlen) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(6, ("decrypt failed"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
          goto cleanup_and_return;
        }
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
                      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
                      SSH_FORMAT_END);
    }
  else
    {
      SSH_DEBUG(3, ("unknown op '%.50s'", op_name));
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
    }

 cleanup_and_return:
  return;
}


/* This function is called whenever the agent receives a packet from a client.
   This will process the request, and eventually send a response. */
void ssh_agenti_received_packet(SshCrossPacketType type,
                                const unsigned char *data, size_t len,
                                void *context)
{
  SshAgentConnection conn = (SshAgentConnection)context;
  unsigned char *private_blob, *public_blob;
  size_t bytes, private_len, public_len, password_len;
  char *description, *op_name, *forwarding_host, *password;
  SshUInt32 timeout_time;
  SshTime current_time;
  SshBuffer buffer;
  unsigned int byte;
  struct SshAgentKeyAttrsRec attrs;

  SSH_DEBUG(7, ("type=%d data=0x%p len=%d ctx=0x%p",
                type, data, len, context));

  switch ((int)type)
    {
    case SSH_AGENT_REQUEST_VERSION:
      SSH_DEBUG(7, ("version request with path '%s' path_len = %d",
                    (conn->forwarding_path ?
                     conn->forwarding_path :
                     "(local)"),
                    conn->forwarding_path_len));
#ifdef WITH_SSH_AGENT1_COMPAT
      if (conn->agent->ssh1_compat && (len == 0))
        {
          SSH_DEBUG(7, ("translate it to ssh1 query."));
          /* No lock check here.  Handler function sends the empty list. */
          ssh_agenti_handle_ssh1_packet(conn, 
                                        SSH1_AGENT_LIST_KEYS, 
                                        data, 
                                        len);
        }
      else
#endif /* WITH_SSH_AGENT1_COMPAT */
        {
          /* If len != 0 here, the remote version string could be decoded
             from the query packet as a SSH_FORMAT_UINT32_STR string.
             No need to actually do that, but it gives a distinction
             to ssh1 agent queries.  Remember that ssh2 versions older
             than ssh-2.0.11 don't add version string here, so this
             agent run with ssh1_compat don't work with them.  Without
             ssh1_compat flag, this agent works also with older ssh2
             versions.  //tri */
          /* Send our version number. */
          ssh_agenti_send(conn, SSH_AGENT_VERSION_RESPONSE,
                          SSH_FORMAT_UINT32, (SshUInt32) 2,
                          SSH_FORMAT_END);
        }
      break;

    case SSH_AGENT_ADD_KEY:
      if (conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
          break;
        }
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32_STR,
                               &private_blob, &private_len,
                               SSH_FORMAT_UINT32_STR,
                               &public_blob, &public_len,
                               SSH_FORMAT_UINT32_STR, &description, NULL,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          SSH_DEBUG(3, ("ADD_KEY bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      else if (bytes == len)
        {
          if (ssh_agenti_add_key(conn->agent, private_blob, private_len,
                                 NULL, public_blob, public_len, description,
                                 NULL,
                                 FALSE))
            ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
          else
            ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
          break;
        }
      ssh_agent_init_key_attrs(&attrs);
      current_time = ssh_time();

      ssh_buffer_init(&buffer);
      ssh_buffer_append(&buffer, &(data[bytes]), len - bytes);

      while (1)
        {
          if (ssh_decode_buffer(&buffer,
                                SSH_FORMAT_CHAR, &byte,
                                SSH_FORMAT_END) != 1)
            {
              SSH_DEBUG(3, ("ADD_KEY bad constraint data"));
              ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
              goto end_of_attrs;
            }
          switch (byte)
            {
            case SSH_AGENT_CONSTRAINT_OLD_TIMEOUT:
            case SSH_AGENT_CONSTRAINT_TIMEOUT:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_TIMEOUT"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_UINT32, &timeout_time,
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (timeout) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              attrs.timeout_time = (SshTime)timeout_time + current_time;
              break;

            case SSH_AGENT_CONSTRAINT_OLD_USE_LIMIT:
            case SSH_AGENT_CONSTRAINT_USE_LIMIT:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_USE_LIMIT"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_UINT32, &(attrs.use_limit),
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (use limit) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              break;

            case SSH_AGENT_CONSTRAINT_OLD_FORWARDING_STEPS:
            case SSH_AGENT_CONSTRAINT_FORWARDING_STEPS:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_FORWARDING_STEPS"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_UINT32, 
                                    &(attrs.path_len_limit),
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (path length) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              break;

            case SSH_AGENT_CONSTRAINT_OLD_FORWARDING_PATH:
            case SSH_AGENT_CONSTRAINT_FORWARDING_PATH:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_FORWARDING_PATH"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_UINT32_STR,
                                    &(attrs.path_constraint), NULL,
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (path) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              break;

            case SSH_AGENT_CONSTRAINT_OLD_COMPAT:
            case SSH_AGENT_CONSTRAINT_COMPAT:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_COMPAT"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_BOOLEAN, 
                                    &(attrs.compat_allowed),
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (path) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              break;

            case SSH_AGENT_CONSTRAINT_OLD_STATUS:
            case SSH_AGENT_CONSTRAINT_STATUS:
              SSH_DEBUG(7, ("got attr SSH_AGENT_CONSTRAINT_STATUS"));
              if (ssh_decode_buffer(&buffer,
                                    SSH_FORMAT_UINT32, &(attrs.status),
                                    SSH_FORMAT_END) == 0)
                {
                  SSH_DEBUG(3, ("ADD_KEY bad constraint (status) data"));
                  ssh_agenti_send_error(conn, 
                                        SSH_AGENT_ERROR_UNSUPPORTED_OP);
                  goto end_of_attrs;
                }
              break;

            default:
              SSH_DEBUG(3, ("ADD_KEY bad constraint attribute type %d",
                            byte));
              ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
              goto end_of_attrs;
            }
          if (ssh_buffer_len(&buffer) == 0)
            {
              if (ssh_agenti_add_key(conn->agent, 
                                     private_blob, private_len, 
                                     NULL, 
                                     public_blob, public_len, 
                                     description,
                                     &attrs,
                                     FALSE))
                {
                  SSH_DEBUG(5, ("ADD_KEY key addition ok"));
                  ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
                }
              else
                {
                  SSH_DEBUG(5, ("ADD_KEY key addition failed"));
                  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
                }
              goto end_of_attrs;
            }
        }

    end_of_attrs:
      ssh_buffer_uninit(&buffer);
      break;

    case SSH_AGENT_DELETE_ALL_KEYS:
      if (conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
          break;
        }
      if (len != 0)
        {
          SSH_DEBUG(3, ("DELETE_ALL_KEYS bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      ssh_agenti_delete_keys(conn->agent);
      ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
      break;
      
    case SSH_AGENT_DELETE_KEY:
      if (conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
          break;
        }
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR,
                           &public_blob, &public_len,
                           SSH_FORMAT_UINT32_STR,
                           &description, NULL,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("DELETE_KEY bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      if (public_len > 0)
        {
          ssh_xfree(description);
          if (ssh_agenti_delete_key(conn->agent, public_blob, public_len))
            ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
          else
            ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
        }
      else
        {
          /* It's an URL.  Cannot process them. */
          ssh_xfree(description);
          ssh_xfree(public_blob);
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
        }
      break;

    case SSH_AGENT_LIST_KEYS:
      /* No lock check here.  Handler function sends the empty list. */
      if (len != 0)
        {
          SSH_DEBUG(3, ("LIST_KEYS bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      ssh_agenti_list_keys(conn);
      break;
      
    case SSH_AGENT_PRIVATE_KEY_OP:
      if (conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
          break;
        }
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_UINT32_STR, &op_name, NULL,
                               SSH_FORMAT_UINT32_STR,
                               &public_blob, &public_len,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          SSH_DEBUG(3, ("PRIVATE_KEY_OP bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      ssh_agenti_private_key_op(conn, op_name, public_blob, public_len,
                                data + bytes, len - bytes);
      break;

    case SSH_AGENT_LOCK:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &password, NULL,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("LOCK bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      if (conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
        }
      else
        {
          conn->agent->lock_password = password;
          ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
        }
      break;

    case SSH_AGENT_UNLOCK:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &password, &password_len,
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("UNLOCK bad data"));
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
          break;
        }
      if (! conn->agent->lock_password)
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
        }
      else if (strcmp(conn->agent->lock_password, password) == 0)
        {
          memset(conn->agent->lock_password, 
                 'F', 
                 strlen(conn->agent->lock_password));
          ssh_xfree(conn->agent->lock_password);
          conn->agent->lock_password = NULL;
          ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
        }
      else
        {
          ssh_agenti_send_error(conn, SSH_AGENT_ERROR_DENIED);
        }
      memset(password, 'F', password_len);
      ssh_xfree(password);
      break;

    case SSH_AGENT_PING:
      ssh_agenti_send(conn, SSH_AGENT_ALIVE,
                      SSH_FORMAT_DATA, data, len,
                      SSH_FORMAT_END);
      break;

    case SSH_AGENT_FORWARDING_NOTICE:
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &forwarding_host, NULL,
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           SSH_FORMAT_UINT32, NULL, /* port */
                           SSH_FORMAT_END) != len)
        {
          SSH_DEBUG(3, ("FORWARDING_NOTICE bad data"));
          break;
        }
      if (conn->forwarding_path == NULL)
        {
          conn->forwarding_path = forwarding_host;
        }
      else
        {
          conn->forwarding_path = ssh_xrealloc(conn->forwarding_path,
                                               strlen(conn->forwarding_path) +
                                               strlen(forwarding_host) + 2);
          strcat(conn->forwarding_path, ",");
          strcat(conn->forwarding_path, forwarding_host);
          ssh_xfree(forwarding_host);
        }
      conn->forwarding_path_len++;
      break;
      
#ifdef WITH_SSH_AGENT1_COMPAT
    case SSH1_AGENT_AUTH_CHALLENGE:
    case SSH1_AGENT_ADD_KEY:
    case SSH1_AGENT_REMOVE_KEY:
    case SSH1_AGENT_REMOVE_ALL_KEYS:
      if (conn->agent->lock_password)
        {
          ssh_agenti_send(conn, SSH1_AGENT_FAILURE, SSH_FORMAT_END);
          break;
        }
      ssh_agenti_handle_ssh1_packet(conn, type, data, len);
      break;
#endif /* WITH_SSH_AGENT1_COMPAT */
    default:
      if ((((int)type) >= 130) && (((int)type) <= 199))
        break; /* Unknown notification or request is ignored. */
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
      break;
    }
}

/* This fuction is called when eof is received from agent connection. */
void ssh_agenti_received_eof(void *context)
{
  SshAgentConnection conn, *connp;

  conn = (SshAgentConnection)context;
  
  /* Remove from list of active connections. */
  for (connp = &conn->agent->connections; *connp && *connp != conn;
       connp = &(*connp)->next)
    ;
  if (!*connp)
    ssh_fatal("ssh_agenti_received_eof: connection %lx not found",
              (unsigned long)conn);
  assert(*connp == conn);
  *connp = conn->next;

  /* Destroy and free the object.  This also closes the stream. */
  ssh_cross_down_destroy(conn->down);
  if (conn->forwarding_path)
    ssh_xfree(conn->forwarding_path);
  memset(conn, 'F', sizeof(*conn));
  ssh_xfree(conn);
}

/* Processes a new incoming connection to the agent.  This is called when
   a new client connects. */
void ssh_agenti_connection(SshStream stream, void *context)
{
  SshAgentImpl agent = (SshAgentImpl)context;
  SshAgentConnection conn;

  conn = ssh_xcalloc(1, sizeof(*conn));
  conn->down = ssh_cross_down_create(stream,
                                     ssh_agenti_received_packet,
                                     ssh_agenti_received_eof,
                                     NULL,
                                     (void *)conn);
  conn->next = agent->connections;
  agent->connections = conn;
  conn->agent = agent;
  ssh_cross_down_can_receive(conn->down, TRUE);
}

/* Creates the authentication agent and starts listening for connections. */
SshAgentImpl ssh_agenti_create(char **path_return)
{
  SshAgentImpl agent;

  agent = ssh_xcalloc(1, sizeof(*agent));
  agent->connections = NULL;
  agent->random_state = NULL;
  agent->lock_password = NULL; /* Not locked */
  agent->listener = ssh_agenti_create_listener(getuid(), path_return,
                                               ssh_agenti_connection,
                                               FALSE,
                                               (void *)agent);
#ifdef WITH_SSH_AGENT1_COMPAT
  agent->ssh1_compat = FALSE;
#endif /* WITH_SSH_AGENT1_COMPAT */

  if (!agent->listener)
    {
      ssh_xfree(agent);
      return NULL;
    }
  return agent;
}

/* This is called periodically by a timeout in order to delete keys
   that are expored.  This timeout can also be called from private
   key operations in order to avoid using the expired key. */
void ssh_agenti_check_timeout_keys(void *context)
{
  SshAgentImpl agent = (SshAgentImpl)context;
  SshAgentKey key;
  SshAgentKey tmpkey = NULL;
  SshAgentKey newkey = NULL;
  SshTime ct;

  SSH_DEBUG(7, ("checking for expired keys"));

  ct = ssh_time();

  /* Remove the key with given certs */
  for (tmpkey = agent->keys; tmpkey; /*NOTHING*/)
    {
      key = tmpkey;
      tmpkey = key->next;
      if ((key->attr.timeout_time == 0) || (key->attr.timeout_time > ct))
        {
          key->next = newkey;
          newkey = key;
        }
      else
        {
          SSH_DEBUG(7, ("expired key removed"));
        }
    }
  agent->keys = newkey;
  newkey = NULL;

  /* Turn the list over to restore original order */
  for (tmpkey = agent->keys; tmpkey; /*NOTHING*/)
    {
      key = tmpkey;
      tmpkey = key->next;
      key->next = newkey;
      newkey = key;
    }
  agent->keys = newkey;

  /* Re-register timeout */
  ssh_register_timeout(SSH_AGENT_CHECK_EXPIRED_KEYS_INTERVAL,
                       0,
                       ssh_agenti_check_timeout_keys,
                       (void *)agent);
}

/* This is called periodically by a timeout, and checks whether the parent
   process is still alive. */
void ssh_agenti_check_parent(void *context)
{
  SshAgentImpl agent = (SshAgentImpl)context;
  
  /* Try to send a dummy signal to the parent process. */
  if (kill(getppid(), 0) < 0)
    {
      remove(agent->socket_name);
      if (strchr(agent->socket_name, '/'))
        *strrchr(agent->socket_name, '/') = '\0';
      rmdir(agent->socket_name); /* may fail if there are other sockets in it*/
      /* Note: instead of doing ssh_event_loop_abort we call exit here.  This
         is to avoid the possibility that someone leaves a connection to the
         agent open and could exploit the keys after the legitimate user has
         logged off. */
      exit(1);
    }

  /* Re-schedule this timeout. */
  ssh_register_timeout(SSH_AGENT_CHECK_PARENT_INTERVAL, 
                       0, 
                       ssh_agenti_check_parent,
                       (void *)agent);
}

/* Return TRUE if agent forwarding path is too long for given key
   or if the key has expired. */
Boolean ssh_agenti_invalid_key(SshAgentConnection conn, 
                               SshAgentKeyAttrs attrs)
{
  SshTime current_time;

  if ((attrs->path_len_limit != 0xffffffff) &&
      (attrs->path_len_limit < conn->forwarding_path_len))
    {
      SSH_DEBUG(7, ("denied for limited path len"));
      return TRUE;      
    }
  else
    {
      SSH_DEBUG(7, ("key path len ok"));
    }
  
  current_time = ssh_time();
  if ((attrs->timeout_time != 0) &&
      (attrs->timeout_time <= current_time))
    {
      SSH_DEBUG(7, ("denied for expired key"));
      return TRUE;      
    }
  else
    {
      SSH_DEBUG(7, ("key timeout nonexisting or not yet exceeded"));
    }
  
  if (! ssh_agent_path_match(attrs->path_constraint, 
                             conn->forwarding_path))
    {
      SSH_DEBUG(7, ("denied because forwarding path do not match constraint"));
      return TRUE;
    }
  else
    {
      SSH_DEBUG(7, ("forwarding path matches constraint"));
    }

  return FALSE;
}

static void usage(void);
static void usage()
{
  fprintf(stderr, "Usage: ssh-agent [-c] [-s] [-1] [command [args...]]\n");
  exit(1);
}

/* Main program for the unix version of the agent. */

int main(int argc, char **argv)
{
  int binsh = 1, opt;
  char *socket_name;
  char buf[100];
  SshAgentImpl agent;
  int pid;
  SshUser user;
  Boolean debug_mode;
#ifdef WITH_SSH_AGENT1_COMPAT
  Boolean ssh1_compat = FALSE;
#endif /* WITH_SSH_AGENT1_COMPAT */

  /* Save program name. */
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  /* Get user database information for the current user. */
  user = ssh_user_initialize(NULL, FALSE);
  debug_mode = FALSE;
  
#define SSH_AGENT_GETOPT_OPTIONS "csd:u:1"

  while ((opt = ssh_getopt(argc, argv, SSH_AGENT_GETOPT_OPTIONS, NULL)) != -1)
    {
      if (!ssh_optval)
        {
          usage();
        }
      switch (opt)
        {
        case 'c':
          binsh = 0;
          break;
        case 's':
          binsh = 1;
          break;
        case 'd':
          debug_mode = TRUE;
          ssh_debug_set_level_string(ssh_optarg);
          break;
        case '1':
#ifdef WITH_SSH_AGENT1_COMPAT
          ssh1_compat = TRUE;
#else /* WITH_SSH_AGENT1_COMPAT */
          ssh_warning("warning: ssh-agent1 compatibility not supported.\n");
#endif /* WITH_SSH_AGENT1_COMPAT */
          break;  
        default:
          fprintf(stderr, "%s: unknown option '%c'.\n", av0, ssh_optopt);
          usage();
          exit(1);
        }
    }

  /* Ignore broken pipe signals. */
  signal(SIGPIPE, SIG_IGN);

  /* Initialize the event loop. */
  ssh_event_loop_initialize();

  /* Determine the path of the agent socket and create the agent. */
  agent = ssh_agenti_create(&socket_name);
#ifdef WITH_SSH_AGENT1_COMPAT
  agent->ssh1_compat = ssh1_compat;
#endif /* WITH_SSH_AGENT1_COMPAT */

  if (agent == NULL)
    {
      /* Agent creation failed.  If we don't have a command, just return
         error.  Otherwise, give an error but still execute the command.
         (This is more robust than existing, as the agent is often started
         during loging.) */
      if (ssh_optind >= argc)
        {
          ssh_fatal("Cannot safely create agent socket '%s'", socket_name);
        }
      else
        {
          ssh_warning("Cannot safely create agent socket '%s'", socket_name);
          execvp(argv[ssh_optind], argv + ssh_optind);
          perror(argv[ssh_optind]);
          exit(1);
        }
    }

  /* We have now created the agent.  Fork a child to be the agent. */
  if (debug_mode)
    pid = 0;
  else
    pid = fork();
  if (pid != 0)
    {
      /* Close our copy of the agent listener, so that it will get really
         closed when the parent exits. */
      ssh_local_destroy_listener(agent->listener);
      
      /* Exit or exec the command. */
      if (ssh_optind >= argc)
        {
          /* No arguments - print environment variable setting commands
             and exit. */
          if (binsh)
            {
              printf("%s=%s; export %s;\n",
                     SSH_AGENT_VAR, socket_name, SSH_AGENT_VAR);
              printf("%s=%lu; export %s;\n", 
                     SSH_AGENT_PID, (unsigned long)pid, SSH_AGENT_PID);
#ifdef WITH_SSH_AGENT1_COMPAT
              if (ssh1_compat)
                {
                  if (strcmp(SSH1_AGENT_VAR, SSH_AGENT_VAR) != 0)
                    printf("%s=%s; export %s;\n",
                           SSH1_AGENT_VAR, socket_name, SSH1_AGENT_VAR);
                  if (strcmp(SSH1_AGENT_PID, SSH_AGENT_PID) != 0)
                    printf("%s=%lu; export %s;\n", 
                           SSH1_AGENT_PID, (unsigned long)pid, SSH1_AGENT_PID);
                }
#endif /* WITH_SSH_AGENT1_COMPAT */
              printf("echo Agent pid %lu;\n", (unsigned long)pid);
            }
          else
            {                   /* shell is *csh */
              printf("setenv %s %s;\n", SSH_AGENT_VAR, socket_name);
              printf("setenv %s %lu;\n", SSH_AGENT_PID, (unsigned long)pid);
#ifdef WITH_SSH_AGENT1_COMPAT
              if (ssh1_compat)
                {
                  if (strcmp(SSH1_AGENT_VAR, SSH_AGENT_VAR) != 0)
                    printf("setenv %s %s;\n", SSH1_AGENT_VAR, socket_name);
                  if (strcmp(SSH1_AGENT_PID, SSH_AGENT_PID) != 0)
                    printf("setenv %s %lu;\n", 
                           SSH1_AGENT_PID, (unsigned long)pid);
                }
#endif /* WITH_SSH_AGENT1_COMPAT */
              printf("echo Agent pid %lu;\n", (unsigned long)pid);
            }
          exit(0);
        }
      else
        {
          /* We have a command.  Put the new environment variables in
             environment and exec the command. */
          snprintf(buf, sizeof(buf), "%s=%s", SSH_AGENT_VAR, socket_name);
          putenv(ssh_xstrdup(buf));
          snprintf(buf, sizeof(buf), "%s=%lu",
                   SSH_AGENT_PID, (unsigned long)pid);
          putenv(ssh_xstrdup(buf));
#ifdef WITH_SSH_AGENT1_COMPAT
              if (ssh1_compat)
                {
                  if (strcmp(SSH1_AGENT_VAR, SSH_AGENT_VAR) != 0)
                    {
                      snprintf(buf, sizeof(buf), "%s=%s", 
                               SSH1_AGENT_VAR, socket_name);
                      putenv(ssh_xstrdup(buf));
                    }
                  if (strcmp(SSH1_AGENT_PID, SSH_AGENT_PID) != 0)
                    {
                      snprintf(buf, sizeof(buf), "%s=%lu",
                               SSH1_AGENT_PID, (unsigned long)pid);
                      putenv(ssh_xstrdup(buf));
                    }
                }
#endif /* WITH_SSH_AGENT1_COMPAT */
          execvp(argv[ssh_optind], argv + ssh_optind);
          perror(argv[ssh_optind]);
          exit(1);
        }
    }

  chdir("/");

  /* We are the child, and become the agent. */
  if (!debug_mode)
    {
      close(0);
      close(1);
      close(2);
    }
  else
    {
      printf("#\n# Running in debug mode.\n#\n");
      if (binsh)
        {
          printf("%s=%s; export %s;\n",
                 SSH_AGENT_VAR, socket_name, SSH_AGENT_VAR);
          printf("%s=%lu; export %s;\n", 
                 SSH_AGENT_PID, (unsigned long)getpid(), SSH_AGENT_PID);
#ifdef WITH_SSH_AGENT1_COMPAT
          if (ssh1_compat)
            {
              if (strcmp(SSH1_AGENT_VAR, SSH_AGENT_VAR) != 0)
                printf("%s=%s; export %s;\n",
                       SSH1_AGENT_VAR, socket_name, SSH1_AGENT_VAR);
              if (strcmp(SSH1_AGENT_PID, SSH_AGENT_PID) != 0)
                printf("%s=%lu; export %s;\n", 
                       SSH1_AGENT_PID, 
                       (unsigned long)getpid(),
                       SSH1_AGENT_PID);
            }
#endif /* WITH_SSH_AGENT1_COMPAT */
          printf("echo Agent pid %lu;\n", (unsigned long)getpid());
        }
      else
        {                   /* shell is *csh */
          printf("setenv %s %s;\n", SSH_AGENT_VAR, socket_name);
          printf("setenv %s %lu;\n", SSH_AGENT_PID, (unsigned long)getpid());
#ifdef WITH_SSH_AGENT1_COMPAT
          if (ssh1_compat)
            {
              if (strcmp(SSH1_AGENT_VAR, SSH_AGENT_VAR) != 0)
                printf("setenv %s %s;\n", SSH1_AGENT_VAR, socket_name);
              if (strcmp(SSH1_AGENT_PID, SSH_AGENT_PID) != 0)
                printf("setenv %s %lu;\n",
                       SSH1_AGENT_PID, (unsigned long)getpid());
            }
#endif /* WITH_SSH_AGENT1_COMPAT */
          printf("echo Agent pid %lu;\n", (unsigned long)getpid());
        }
    }
  
  if (!debug_mode)
    {
  /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
      {
        int fd;
#ifdef O_NOCTTY
        fd = open("/dev/tty", O_RDWR | O_NOCTTY);
#else
        fd = open("/dev/tty", O_RDWR);
#endif
        if (fd >= 0)
          {
            (void)ioctl(fd, TIOCNOTTY, NULL);
            close(fd);
          }
      }
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
        ssh_warning("setsid: %.100s", strerror(errno));
#endif
#endif /* HAVE_SETSID */
    }

  agent->socket_name = ssh_xstrdup(socket_name);

  /* Load the random seed file. */
  agent->random_state = ssh_randseed_open(user, NULL);

  /* Register a timeout to periodically check whether the parent has
     exited (which means we should exit too). */
  if (ssh_optind < argc)
    {
      ssh_register_timeout(SSH_AGENT_CHECK_PARENT_INTERVAL, 
                           0, 
                           ssh_agenti_check_parent,
                           (void *)agent);
    }

  /* Register timeout to remove expired keys from the memory. */
  ssh_register_timeout(SSH_AGENT_CHECK_EXPIRED_KEYS_INTERVAL,
                       0,
                       ssh_agenti_check_timeout_keys,
                       (void *)agent);

  /* Keep running the event loop until we exit. */
  ssh_event_loop_run();

  /* Uninitialize the event loop. */
  ssh_event_loop_uninitialize();

  if (agent->random_state)
    {
      /* Update the random seed file. */
      ssh_randseed_update(user, agent->random_state, NULL);
      /* Free the random seed. */
      ssh_random_free(agent->random_state);
    }

  /* Free user database information about the current user. */
  ssh_user_free(user, FALSE);

  /* Remove the socket that we listened on. */
  remove(agent->socket_name);
  if (strchr(agent->socket_name, '/'))
    *strrchr(agent->socket_name, '/') = '\0';
  rmdir(agent->socket_name); /* This may fail if there are other sockets. */
  
  /* Exit. */
  return 0;
}

#ifdef WITH_SSH_AGENT1_COMPAT
void ssh_agenti_ssh1_encode_mp(SshBuffer *buffer, SshInt *n)
{
  SshUInt32 len;
  unsigned char len_buf[2];
  unsigned char *num_buf;
  size_t num_buf_len;

  len = ssh_mp_get_size(n, 2);
  len_buf[0] = (len >> 8) & 0xff;
  len_buf[1] = len & 0xff;

  num_buf_len = ((len + 7) >> 3) & 0xffff;
  num_buf = ssh_xmalloc(num_buf_len);
  ssh_mp_get_buf(num_buf, num_buf_len, n);
  ssh_encode_buffer(buffer, 
                    SSH_FORMAT_DATA, len_buf, 2,
                    SSH_FORMAT_DATA, num_buf, num_buf_len, 
                    SSH_FORMAT_END);
  ssh_xfree(num_buf);
  return;
}

Boolean ssh_agenti_ssh1_decode_mp(SshBuffer *buffer, SshInt *n)
{
  SshUInt32 len;
  unsigned char *len_buf;
  size_t num_buf_len;

  if (ssh_buffer_len(buffer) < 2)
    return FALSE;
  len_buf = ssh_buffer_ptr(buffer);
  len = (len_buf[0] * 0x100) + len_buf[1];
  num_buf_len = ((len + 7) >> 3) & 0xffff;
  if (ssh_buffer_len(buffer) < (2 + num_buf_len))
    return FALSE;
  ssh_mp_set_buf(n, &(len_buf[2]), num_buf_len);
  ssh_buffer_consume(buffer, num_buf_len + 2);
  return TRUE;
}

void ssh_agenti_ssh1_list_keys(SshAgentConnection conn)
{
  SshAgentKey key;
  SshAgentSsh1Key ssh1_key;
  unsigned long num_keys;
  SshBuffer buffer;
  char *key_name;
  SshPublicKey public_key;
  size_t bits;

  if (conn->agent->lock_password)
    {
      ssh_agenti_send(conn, SSH1_AGENT_KEY_LIST,
                      SSH_FORMAT_UINT32, 
                      (SshUInt32)0,
                      SSH_FORMAT_END);
      return;
    }

  /* Build the list of keys first, counting the keys at the same time. */
  num_keys = 0;
  ssh_buffer_init(&buffer);

  for (ssh1_key = conn->agent->ssh1_keys; ssh1_key; ssh1_key = ssh1_key->next)
    {
      bits = ssh_mp_get_size(&(ssh1_key->n), 2);
      if (bits <= 0x10000)
        {
          num_keys++;
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_UINT32, 
                            (SshUInt32)bits,
                            SSH_FORMAT_END);
          ssh_agenti_ssh1_encode_mp(&buffer, &(ssh1_key->e));
          ssh_agenti_ssh1_encode_mp(&buffer, &(ssh1_key->n));
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_UINT32_STR, 
                            ssh1_key->description, 
                            strlen(ssh1_key->description),
                            SSH_FORMAT_END);
        }
    }
  for (key = conn->agent->keys; key; key = key->next)
    {
      if ((key->attr.compat_allowed) &&
          (! key->ssh1_key_available) &&
          (! ssh_agenti_invalid_key(conn, &(key->attr))))
        {
          if (key->private_key)
            key_name = ssh_private_key_name(key->private_key);
          else
            key_name = NULL;
          SSH_DEBUG(7, ("key name=%s%s%s", 
                        (key_name ? "\"" : ""), 
                        (key_name ? key_name : NULL), 
                        (key_name ? "\"" : "")));
          if (key_name && strstr(key_name, "{rsa-"))
            {
              public_key = ssh_private_key_derive_public_key(key->private_key);
              if (public_key)
                {
                  SshInt n, e;
                  
                  ssh_mp_init(&n);
                  ssh_mp_init(&e);
                  if (ssh_public_key_get_info(public_key,
                                              SSH_PKF_MODULO_N, &n,
                                              SSH_PKF_PUBLIC_E, &e,
                                              SSH_PKF_END) == SSH_CRYPTO_OK)
                    {
                      bits = ssh_mp_get_size(&n, 2);
                      if (bits <= 0x10000)
                        {
                          num_keys++;
                          ssh_encode_buffer(&buffer,
                                            SSH_FORMAT_UINT32, 
                                            (SshUInt32)bits,
                                            SSH_FORMAT_END);
                          ssh_agenti_ssh1_encode_mp(&buffer, &e);
                          ssh_agenti_ssh1_encode_mp(&buffer, &n);
                          ssh_encode_buffer(&buffer,
                                            SSH_FORMAT_UINT32_STR, 
                                            key->description, 
                                            strlen(key->description),
                                            SSH_FORMAT_END);
                        }
                    }
                  ssh_mp_clear(&n);
                  ssh_mp_clear(&e);
                  ssh_public_key_free(public_key);
                }
            }
          else
            {
          SSH_DEBUG(7, ("skipping non-rsa key"));
            }
        }
      else
        {
          SSH_DEBUG(7, ("skipping key for restriction"));
        }
    }

  ssh_agenti_send(conn, SSH1_AGENT_KEY_LIST,
                  SSH_FORMAT_UINT32, 
                  (SshUInt32)num_keys,
                  SSH_FORMAT_DATA, 
                  ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer), 
                  SSH_FORMAT_END);
  ssh_buffer_uninit(&buffer);
}

void ssh_agenti_ssh1_challenge(SshAgentConnection conn, 
                                   const unsigned char *data, 
                                   size_t len)
{
  SshInt e, n, challenge, output;
  SshBuffer buffer;
  SshBuffer reply;
  SshUInt32 bits;
  SshPublicKey public_key = NULL;
  unsigned char *public_blob = NULL;
  unsigned char *output_buf = NULL;
  unsigned char *challenge_buf = NULL;
  unsigned char *session_id = NULL;
  unsigned char *output_digest = NULL;
  size_t public_blob_len, output_len, challenge_len, output_digest_len;
  SshHash hash;
  SshAgentKey key = NULL;
  SshAgentSsh1Key ssh1_key = NULL;
  SshUInt32 response_type;
  Boolean success = FALSE;
  SshCryptoStatus cr;

  ssh_buffer_init(&buffer);
  ssh_buffer_init(&reply);
  ssh_buffer_append(&buffer, data, len);
  ssh_mp_init(&n);
  ssh_mp_init(&e);
  ssh_mp_init(&challenge);
  ssh_mp_init(&output);

  SSH_DEBUG(7, ("got ssh1 challenge from the server"));

  /* Decode packet data */
  if (ssh_decode_buffer(&buffer, 
                        SSH_FORMAT_UINT32, &bits,
                        SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(3, ("failed to decode challenge key"));
      goto cleanup_reply_and_return;
    }
  if (! (ssh_agenti_ssh1_decode_mp(&buffer, &e) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &n) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &challenge)))
    {
      SSH_DEBUG(3, ("failed to decode challenge"));
      goto cleanup_reply_and_return;
    }

  /* Get response type and session_id */
  if (ssh_buffer_len(&buffer) >= 20)
    {
      session_id = ssh_xmalloc(16);
      if (ssh_decode_buffer(&buffer, 
                            SSH_FORMAT_DATA, session_id, 16,
                            SSH_FORMAT_UINT32, &response_type,
                            SSH_FORMAT_END) == 0) 
        {
          SSH_DEBUG(3, ("failed to decode session id"));
          goto cleanup_reply_and_return;
        }
    }
  else
    {
      response_type = 0;
      session_id = ssh_xmalloc(16);
      memset(session_id, 0, 16);
    }
  ssh1_key = ssh_agenti_ssh1key_find(conn->agent, &n, &e);
  if (ssh1_key)
    {
      SSH_DEBUG(7, ("Using ssh1 key to decrypt challenge."));
      /* Decrypt the challenge. */
      ssh_mp_powm(&output, &challenge, &(ssh1_key->d), &(ssh1_key->n));
      /* Linearize the output */
      output_len = ((ssh_mp_get_size(&output, 2) + 7) >> 3) & 0xffff;
      if (output_len == 0)
        {
          SSH_DEBUG(6, ("failed to linearize the decrypted challenge"));
          goto cleanup_reply_and_return;
        }
      if (output_len < 32)
        output_len = 32;
      output_buf = ssh_xcalloc(output_len, sizeof (unsigned char));
      ssh_mp_get_buf(output_buf, output_len, &output);
      /* Use at most lowest 32 bytes (256 bits) of the output. */
      if (output_len > 32)
        {
          memcpy(output_buf, &(output_buf[output_len - 32]), 32);
          output_len = 32;
        }
      SSH_DEBUG_HEXDUMP(9, ("Decrypted (internal) ssh1 challenge"), 
                        output_buf, output_len);
    }
  else
    {
      SSH_DEBUG(7, ("Attempting to use ssh2 key to decrypt challenge."));
      /* Make public key */
      cr = ssh_public_key_define(&public_key, 
                                 SSH_CRYPTO_RSA, 
                                 SSH_PKF_MODULO_N, &n,
                                 SSH_PKF_PUBLIC_E, &e,
                                 SSH_PKF_END);
      if (cr != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(6, ("failed to make public key (%d)", (int)cr));
          goto cleanup_reply_and_return;
        }

      /* Linearize the public key to blob */
      if ((public_blob_len = 
           ssh_encode_pubkeyblob(public_key, &public_blob)) == 0)
        {
          SSH_DEBUG(6, ("failed to linearize public key"));
          goto cleanup_reply_and_return;
        }

      /* Search the key */
      key = ssh_agenti_find_key(conn->agent, 
                                public_blob,
                                public_blob_len, 
                                TRUE);
      if (key == NULL)
        {
          SSH_DEBUG(5, ("failed to find secret key"));
          goto cleanup_reply_and_return;
        }
      else if (! key->attr.compat_allowed ||
               ssh_agenti_invalid_key(conn, &(key->attr)))
        {
          SSH_DEBUG(5, ("secret key not available for restriction"));
          goto cleanup_reply_and_return;
        }

      /* Linearize the challenge */
      challenge_len = ((ssh_mp_get_size(&challenge, 2) + 7) >> 3) & 0xffff;
      if (challenge_len == 0)
        {
          SSH_DEBUG(6, ("failed to linearize the challenge"));
          goto cleanup_reply_and_return;
        }
      challenge_buf = ssh_xmalloc(challenge_len);
      ssh_mp_get_buf(challenge_buf, challenge_len, &challenge);

      /* Decrypt challenge */
      output_len = ssh_private_key_max_decrypt_output_len(key->private_key);
      if (output_len == 0)
        {
          SSH_DEBUG(6, ("failed to define output length"));
          goto cleanup_reply_and_return;
        }

      output_buf = ssh_xmalloc(output_len);
      cr = ssh_private_key_decrypt(key->private_key, 
                                   challenge_buf, challenge_len,
                                   output_buf, output_len,
                                   &output_len);
      if (cr != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(6, ("failed to decrypt ssh1 challenge (%d)", 
                        (int)cr));
          goto cleanup_reply_and_return;
        }
      SSH_DEBUG_HEXDUMP(9, ("Decrypted (crypto lib) ssh1 challenge"), 
                        output_buf, output_len);
    }
  /* Compute the desired response. */
  switch (response_type)
    {
    case 0: /* As of protocol 1.0 */
      /* This response type is no longer supported even in ssh-1.2.X. */
      SSH_DEBUG(3, ("denied nonsupported type 0 ssh1 challenge"));
      goto cleanup_reply_and_return;
    case 1: /* As of protocol 1.1 */
      {
        SSH_DEBUG(7, ("calculating type 1 ssh1 challenge"));
        cr = ssh_hash_allocate("md5", &hash);
        if (cr != SSH_CRYPTO_OK)
          {
            SSH_DEBUG(6, ("ssh_hash_allocate failed (%d)", (int)cr));
            goto cleanup_reply_and_return;
          }
        ssh_hash_update(hash, output_buf, (output_len < 32) ? output_len : 32);
        ssh_hash_update(hash, session_id, 16);
        output_digest_len = ssh_hash_digest_length(hash);
        output_digest = ssh_xmalloc(output_digest_len);
        ssh_hash_final(hash, output_digest);
        ssh_hash_free(hash);
        ssh_buffer_append(&reply, output_digest, output_digest_len);
        success = TRUE;
        break;
      }
    default:
      /* Unknown response type. */
      SSH_DEBUG(3, ("unknown ssh1 challenge type %d", (int)response_type));
      goto cleanup_reply_and_return;
    }

  SSH_DEBUG(7, ("sending supposedly correct ssh1 challenge reply"));

 cleanup_reply_and_return:
  ssh_buffer_uninit(&buffer);
  ssh_mp_clear(&n);
  ssh_mp_clear(&e);
  ssh_mp_clear(&challenge);
  ssh_mp_clear(&output);
  if (public_key)
    ssh_public_key_free(public_key);
  ssh_xfree(public_blob);
  ssh_xfree(output_buf);
  ssh_xfree(challenge_buf);
  ssh_xfree(session_id);
  ssh_xfree(output_digest);
  ssh_agenti_send(conn, 
                  (success ? SSH1_AGENT_AUTH_RESPONSE : SSH1_AGENT_FAILURE),
                  SSH_FORMAT_DATA, 
                  ssh_buffer_ptr(&reply), ssh_buffer_len(&reply),
                  SSH_FORMAT_END);
  ssh_buffer_uninit(&reply);
}

void ssh_agenti_ssh1_add_key(SshAgentConnection conn, 
                             const unsigned char *data, 
                             size_t len)
{
  SshBuffer buffer;
  SshInt n, e, d, u, p, q;
  SshUInt32 bits;
  SshPrivateKey private_key = NULL;
  SshPublicKey public_key = NULL;
  char *comment = NULL;
  Boolean success = FALSE;
  unsigned char *public_blob = NULL;
  size_t public_blob_len = 0;

  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, data, len);
  ssh_mp_init(&n);
  ssh_mp_init(&e);
  ssh_mp_init(&d);
  ssh_mp_init(&u);
  ssh_mp_init(&p);
  ssh_mp_init(&q);

  /* Get length of the key (not needed) */
  if (ssh_decode_buffer(&buffer, 
                        SSH_FORMAT_UINT32, &bits,
                        SSH_FORMAT_END) == 0)
    goto cleanup_reply_and_return;

  /* Get key numbers */
  if (! (ssh_agenti_ssh1_decode_mp(&buffer, &n) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &e) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &d) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &u) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &p) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &q)))
    goto cleanup_reply_and_return;

  /* Get key comment */
  if (ssh_decode_buffer(&buffer, 
                        SSH_FORMAT_UINT32_STR, &comment, NULL,
                        SSH_FORMAT_END) == 0)
    goto cleanup_reply_and_return;

  success = ssh_agenti_ssh1key_add(conn->agent, &n, &e, &d, comment);
  /*
   * If there is no RSA support in crypto library, the following
   * ssh_private_key_generate call will fail and the key will
   * be only visible for ssh-agent1.
   */
  /* Create the SSH private key from the extracted numbers */
  if (ssh_private_key_generate(conn->agent->random_state, &private_key,
                               SSH_CRYPTO_RSA,
                               SSH_PKF_SIZE, bits,
                               SSH_PKF_MODULO_N, &n,
                               SSH_PKF_PUBLIC_E, &e,
                               SSH_PKF_SECRET_D, &d,
                               SSH_PKF_INVERSE_U, &u,
                               SSH_PKF_PRIME_P, &p,
                               SSH_PKF_PRIME_Q, &q,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    goto cleanup_reply_and_return;

  /* Create the corresponding public key */
  if ((public_key = ssh_private_key_derive_public_key(private_key)) == NULL)
    goto cleanup_reply_and_return;

  /* Linearize the public key to blob */
  if ((public_blob_len = ssh_encode_pubkeyblob(public_key, &public_blob)) == 0)
    goto cleanup_reply_and_return;

  /* Store key into agent internal database. */
  success = ssh_agenti_add_key(conn->agent,
                               NULL, 0, private_key,
                               public_blob, public_blob_len, 
                               comment,
                               NULL,
                               TRUE);

  /* Following space is freed by ssh_agenti_add_key so we NULL them
     in order to avoid free in cleanup. */
  comment = NULL;
  private_key = NULL;
  public_blob = NULL;

 cleanup_reply_and_return:
  ssh_mp_clear(&n);
  ssh_mp_clear(&e);
  ssh_mp_clear(&d);
  ssh_mp_clear(&u);
  ssh_mp_clear(&p);
  ssh_mp_clear(&q);
  ssh_buffer_uninit(&buffer);
  ssh_xfree(comment);
  ssh_xfree(public_blob);
  if (private_key)
    ssh_private_key_free(private_key);
  if (public_key)
    ssh_public_key_free(public_key);
  ssh_agenti_send(conn, 
                  (success ? SSH1_AGENT_SUCCESS : SSH1_AGENT_FAILURE),
                  SSH_FORMAT_END);
  return;
}

void ssh_agenti_ssh1_remove_key(SshAgentConnection conn, 
                                const unsigned char *data, 
                                size_t len)
{
  SshBuffer buffer;
  SshInt n, e;
  SshUInt32 bits;
  SshPublicKey key = NULL;
  unsigned char *blob = NULL;
  size_t blob_len;
  Boolean success = FALSE;

  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, data, len);
  ssh_mp_init(&n);
  ssh_mp_init(&e);

  /* Get length of the key (not needed) */
  if (ssh_decode_buffer(&buffer, 
                        SSH_FORMAT_UINT32, &bits,
                        SSH_FORMAT_END) == 0)
    goto cleanup_reply_and_return;

  /* Get public key numbers */
  if (! (ssh_agenti_ssh1_decode_mp(&buffer, &e) &&
         ssh_agenti_ssh1_decode_mp(&buffer, &n)))
    goto cleanup_reply_and_return;

  success = ssh_agenti_ssh1key_delete(conn->agent, &n, &e);
  /*
   * If there is no RSA support in crypto library, the following
   * ssh_public_key_define call will fail.  In this case, it's not
   * possible, that key would be in the list in the first place.
   */
  /* Make public key */
  if (ssh_public_key_define(&key, 
                            SSH_CRYPTO_RSA, 
                            SSH_PKF_MODULO_N, &n,
                            SSH_PKF_PUBLIC_E, &e,
                            SSH_PKF_END) != SSH_CRYPTO_OK)
    goto cleanup_reply_and_return;

  /* Linearize the public key to blob */
  if ((blob_len = ssh_encode_pubkeyblob(key, &blob)) == 0)
    goto cleanup_reply_and_return;

  /* Delete the key from the agent */
  success = ssh_agenti_delete_key(conn->agent, blob, blob_len);
  blob = NULL;

 cleanup_reply_and_return:
  ssh_mp_clear(&n);
  ssh_mp_clear(&e);
  if (key)
    ssh_public_key_free(key);
  ssh_buffer_uninit(&buffer);
  ssh_agenti_send(conn, 
                  (success ? SSH1_AGENT_SUCCESS : SSH1_AGENT_FAILURE),
                  SSH_FORMAT_END);
}

void ssh_agenti_ssh1_remove_all_keys(SshAgentConnection conn)
{
  ssh_agenti_delete_keys(conn->agent);
  ssh_agenti_send(conn, SSH1_AGENT_SUCCESS, SSH_FORMAT_END);
}

void ssh_agenti_handle_ssh1_packet(SshAgentConnection conn, 
                                   SshCrossPacketType type,
                                   const unsigned char *data, 
                                   size_t len)
{
  if (! conn->agent->ssh1_compat)
    {
      ssh_agenti_send(conn, SSH1_AGENT_FAILURE, SSH_FORMAT_END);
      return;
    }

  switch (type)
    {
    case SSH1_AGENT_LIST_KEYS:
      ssh_agenti_ssh1_list_keys(conn);
      break;
    case SSH1_AGENT_AUTH_CHALLENGE:
      ssh_agenti_ssh1_challenge(conn, data, len);
      break;
    case SSH1_AGENT_ADD_KEY:
      ssh_agenti_ssh1_add_key(conn, data, len);
      break;
    case SSH1_AGENT_REMOVE_KEY:
      ssh_agenti_ssh1_remove_key(conn, data, len);
      break;
    case SSH1_AGENT_REMOVE_ALL_KEYS:
      ssh_agenti_ssh1_remove_all_keys(conn);
      break;
    default:
      ssh_agenti_send(conn, SSH1_AGENT_FAILURE,
                      SSH_FORMAT_END);
      break;
    }
}

/* Find ssh1 key with the given public part */
SshAgentSsh1Key ssh_agenti_ssh1key_find(SshAgentImpl agent,
                                        SshInt *n, 
                                        SshInt *e)
{
  SshAgentSsh1Key key;

  key = agent->ssh1_keys;
  while (key)
    {
      if ((ssh_mp_cmp(n, &(key->n)) == 0) && (ssh_mp_cmp(e, &(key->e)) == 0))
        return key;
      key = key->next;
    }
  return NULL;
}

/* Adds the given ssh1 private key to be managed by the agent. */
Boolean ssh_agenti_ssh1key_add(SshAgentImpl agent,
                               SshInt *n, 
                               SshInt *e,
                               SshInt *d,
                               char *description)
{
  SshAgentSsh1Key key;

  if (! agent->ssh1_compat)
    return FALSE;
  (void)ssh_agenti_ssh1key_delete(agent, n, e);
  key = ssh_xcalloc(1, sizeof (*key));
  key->description = ssh_xstrdup(description);
  ssh_mp_init_set(&(key->n), n);
  ssh_mp_init_set(&(key->e), e);
  ssh_mp_init_set(&(key->d), d);
  key->next = agent->ssh1_keys;
  agent->ssh1_keys = key;
  return TRUE;
}

/* Delete a ssh1 key with given public key */
Boolean ssh_agenti_ssh1key_delete(SshAgentImpl agent,
                                  SshInt *n, 
                                  SshInt *e)
{
  SshAgentSsh1Key key, prev;
  Boolean success = FALSE;

  prev = NULL;
  key = agent->ssh1_keys;
  while (key)
    {
      if ((ssh_mp_cmp(n, &(key->n)) == 0) && (ssh_mp_cmp(e, &(key->e)) == 0))
        {
          if (prev)
            prev->next = key->next;
          else
            agent->ssh1_keys = key->next;
          ssh_mp_clear(&key->n);
          ssh_mp_clear(&key->e);
          ssh_mp_clear(&key->d);
          ssh_xfree(key->description);
          ssh_xfree(key);
          success = TRUE;
        }
      else
        {
          prev = key;
        }
      key = key->next;
    }
  return success;
}

/* Delete all ssh1 keys */
void ssh_agenti_ssh1key_delete_all(SshAgentImpl agent)
{
  SshAgentSsh1Key key;

  for (key = agent->ssh1_keys; key; key = key->next)
    {
      ssh_mp_clear(&key->n);
      ssh_mp_clear(&key->e);
      ssh_mp_clear(&key->d);
      ssh_xfree(key->description);
      ssh_xfree(key);
    }
  agent->ssh1_keys = NULL;
  return;
}

#endif /* WITH_SSH_AGENT1_COMPAT */

/* eof (ssh-agent2.c) */
