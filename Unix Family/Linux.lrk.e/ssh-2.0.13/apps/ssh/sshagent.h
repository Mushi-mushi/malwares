/*

sshagent.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Interface to the SSH agent.  This header defines the functions that
applications using the agent can call.

*/

#ifndef SSHAGENT_H
#define SSHAGENT_H

#include "sshcrypt.h"

typedef enum {
  SSH_AGENT_ERROR_OK = 0,               /* Operation completed successfully. */
  SSH_AGENT_ERROR_TIMEOUT = 1,          /* Operation timed out. */
  SSH_AGENT_ERROR_KEY_NOT_FOUND = 2,    /* Private key is not available. */
  SSH_AGENT_ERROR_DECRYPT_FAILED = 3,   /* Decryption failed. */
  SSH_AGENT_ERROR_SIZE_ERROR = 4,       /* Data size is inappropriate. */
  SSH_AGENT_ERROR_KEY_NOT_SUITABLE = 5, /* Key is not suitable for request. */
  SSH_AGENT_ERROR_DENIED = 6,           /* Administratively prohibited. */
  SSH_AGENT_ERROR_FAILURE = 7,          /* Unspecific agent error. */
  SSH_AGENT_ERROR_UNSUPPORTED_OP = 8,   /* Operation not supported by agent. */
  SSH_AGENT_ERROR_BUSY                  /* Busy with another operation. */
} SshAgentError;

typedef enum {
  SSH_AGENT_SIGN,                       /* Sign without hashing first. */
  SSH_AGENT_HASH_AND_SIGN,              /* Hash data and then sign hash. */
  SSH_AGENT_DECRYPT,                    /* Decrypt encrypted message. */
  SSH_AGENT_SSH1_CHALLENGE_RESPONSE     /* Respond to ssh1-style challenge. */
} SshAgentOp;

/* Maximum size of key description string. */
#define SSH_AGENT_DESCRIPTION_SIZE      100

typedef struct SshAgentRec *SshAgent;

/* Structure carrying the key attributes */
struct SshAgentKeyAttrsRec
{
  SshUInt32 status; 
  SshUInt32 use_limit;
  SshUInt32 path_len_limit; 
  char *path_constraint;
  SshTime timeout_time;
  Boolean compat_allowed; 
};
typedef struct SshAgentKeyAttrsRec *SshAgentKeyAttrs;

/* Init attribute structure to default values */
void ssh_agent_init_key_attrs(SshAgentKeyAttrs attrs);

/* Checks whether the authentication agent is present.  Returns TRUE if yes.
   This is not completely reliable; this may sometimes return TRUE even if
   the agent is not actually present (in which case ssh_agent_open
   will fail). */
Boolean ssh_agent_present(void);

/* Callback function to be called when a opening a connection to the
   agent completes.  If `agent' is NULL, connecting to the agent failed.
   Otherwise, it is a pointer to an agent connection object that can be
   used to perform operations on the agent. */
typedef void (*SshAgentOpenCallback)(SshAgent agent, void *context);

/* Opens a connection to the authentication agent.  Eventually calls
   the callback with a pointer to the agent structure, or NULL on
   error.  The callback may called either during this call or
   some time later. */
void ssh_agent_open(SshAgentOpenCallback callback, void *context);

/* Closes the connection to the authentication agent.  If a command is
   active, it is terminated and its callback will never be called. */
void ssh_agent_close(SshAgent agent);

/* Callback to be called by operations that return a success/failure result. */
typedef void (*SshAgentCompletion)(SshAgentError result, void *context);

/* Adds the given private key to the agent.  The callback can be NULL. */
void ssh_agent_add(SshAgent agent,
                   SshPrivateKey key,
                   const unsigned char *certs,
                   size_t certs_len,
                   const char description[SSH_AGENT_DESCRIPTION_SIZE],
                   SshAgentCompletion callback, void *context);

/* Adds the given private key to the agent with attributes. 
   The callback can be NULL. */
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
                              void *context);

/* Deletes all the keys from the agent. */
void ssh_agent_delete_all(SshAgent agent, SshAgentCompletion callback,
                          void *context);

/* Deletes the given key from the agent. */
void ssh_agent_delete(SshAgent agent, 
                      const unsigned char *certs, size_t certs_len,
                      const char description[SSH_AGENT_DESCRIPTION_SIZE],
                      SshAgentCompletion callback, void *context);

/* Callback for ssh_agent_list.  This is passed the public keys (or
   certificates) for all private keys that the agent has in its
   possession.  The data will be freed automatically when the callback
   returns, so if it is needed for a longer time, it must be copied
   by the callback. */
typedef struct SshAgentKeyInfoRec {
  char *description;            /* Description of the key */
  const unsigned char *certs;   /* Public key or certificates */
  size_t certs_len;             /* Length of certificates */
} *SshAgentKeyInfo;
typedef void (*SshAgentListCallback)(SshAgentError error,
                                     unsigned int num_keys,
                                     SshAgentKeyInfo keys,
                                     void *context);

/* Returns the public keys for all private keys in possession of the agent.
   Only a single operation may be in progress on the connection at any
   one time. */
void ssh_agent_list(SshAgent agent, SshAgentListCallback callback,
                    void *context);

/* Callback function that is called when a private key operation is
   complete.  The data passed as the argument is only valid until this call
   returns, and this must copy the data if it needs to be accessed after
   returning. */
typedef void (*SshAgentOpCallback)(SshAgentError error,
                                   const unsigned char *result, size_t len,
                                   void *context);

/* Performs a private-key operation using the agent.  Calls the given
   callback when a reply has been received or a timeout occurs.
   Only a single operation may be in progress on the connection at any
   one time.  The caller can free any argument strings as soon as this
   has returned (i.e., no need to wait until the callback has been
   called). */
void ssh_agent_op(SshAgent agent, SshAgentOp op,
                  const unsigned char *certs, size_t certs_len,
                  const unsigned char *data, size_t len,
                  SshAgentOpCallback callback, void *context);

/* Locks the agent with given password */
void ssh_agent_lock(SshAgent agent, const char *password,
                    SshAgentCompletion callback, void *context);

/* Attempts to unlock the agent with given password */
void ssh_agent_unlock(SshAgent agent, const char *password,
                      SshAgentCompletion callback, void *context);

#endif /* SSHAGENT_H */
