/*

sshtrans.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Created: Sat Sep  7 20:11:37 1996 ylo

SSH Transport Layer Protocol interface.

*/

/*
 * $Id: sshtrans.h,v 1.11 1999/04/16 14:40:45 sjl Exp $
 * $Log: sshtrans.h,v $
 * $EndLog$
 */

#ifndef SSHTRANS_H
#define SSHTRANS_H

#include "sshstream.h"
#include "sshcrypt.h"
#include "sshcross.h"

/* This file describes the SSH Transport Layer Protocol interface.
   The transport layer essentially sits between a stream connecting to the
   other side over a network and a stream connecting to higher-level protocols.

   In other words, the transport layer protocol looks like an SshStream object
   wrapped around another SshStream object.  All communication with higher
   level protocols is done by reading/writing this stream.

   A special packet-based protocol called the SSH Cross Layer Protocol
   is used on the stream (see sshcross.h).  This protocol is internal
   to the software implementation, though nothing would prevent
   running it over a TCP/IP connection.

   The transport layer protocol object is started by creating an SshStream
   object using one of the functions below.  From then on, all communication
   with it happens through the stream.  The protocol object is destroyed
   by closing the stream.  The enclosed network-level stream is automatically
   closed when the transport layer stream is closed.

   If creating the transport layer protocol fails, a disconnect message
   can simply be read from the stream.

   After key exchange, if the connection is closed cleanly, an EOF will
   simply be received from the stream.  Otherwise, a disconnect message
   will be received.

   Packets of unknown type should be ignored and forwarded to the next layer.
   Future versions may have additional data in the payload after the fields
   listed here. */

/* Structure for passing additional optional arguments to the functions that
   create transport layer protocol objects.  To maintain compatibility with
   future versions in DLLs, this object should not be created directly but
   by calling ssh_transport_create_params, which will initialize all fields
   to their default values.  Any unchanged fields will use default values.
   Each of the fields is allocated by ssh_xmalloc; when changing them, the old
   value must first be freed with ssh_xfree, and the new value allocated with
   ssh_xmalloc (or ssh_xstrdup). */
typedef struct
{
  char *kex_algorithms;
  char *host_key_algorithms;
  char *hash_algorithms;
  char *compressions_c_to_s;
  char *compressions_s_to_c;
  char *ciphers_c_to_s;
  char *ciphers_s_to_c;
  char *macs_c_to_s;
  char *macs_s_to_c;
} *SshTransportParams;

/* Callback function that is used to check the validity of the server
   host key.
     `server_name'  The server name as passed in when the protocol
                    was created.  This is expected to be the name that
                    the user typed.
     `blob'         The linear representation of the public key (including
                    optional certificates).
     `len'          The length of the public key blob.
     `result_cb'    This function must be called when the validity has been
                    determined.  The argument must be TRUE if the host key
                    is to be accepted, and FALSE if it is to be rejected.
     `result_context' This must be passed to the result function.
     `context'      Context argument.
   This function should call the result callback in every case.  This is not
   allowed to destroy the protocol context.  This function is allowed to
   do basically anything before calling the result callback. */
typedef void (*SshKeyCheckCallback)(const char *server_name,
                                    const unsigned char *blob,
                                    size_t len,
                                    void (*result_cb)(Boolean result,
                                                      void *result_context),
                                    void *result_context,
                                    void *context);

/* Callback function that is called when the remote version has been received.
   This can be used to check for compatibility with older versions and to
   exec an old version as appropriate.  If this returns, the version
   should be compatible, or otherwise the connection will be disconnected.
      `remote_version'     remote version string as received from remote
                           host, but without terminating newline.
      `context'            context argument that was supplied when the
                           callback was registered. */
typedef void (*SshVersionCallback)(const char *remote_version,
                                   void *context);

/* Creates default transport protocol parameter structure.  This structure
   can be modified to choose different parameters. */
SshTransportParams ssh_transport_create_params(void);

/* Frees the protocol parameter structure.  This function should normally not
   be called by applications as the parameters are freed automatically.
   However, if the application gets the parameters just to know what the
   defaults are, it can use this to destroy the parameters. */
void ssh_transport_destroy_params(SshTransportParams params);

/* Takes a stream which is supposed to be a connection to the server, and
   performs client-side processing for the transport layer.  Returns
   a SshStream object representing the transport layer.
     `stream' is the connection to the server; it is automatically closed
        if connection fails or when the transport layer object is destroyed.
     `random_state' is an initialized random state.  It is not automatically
        freed and can be shared with multiple protocol objects.
     `version' is the application version number (e.g. "2.0 rs6000-ibm-aix4.1")
     `service' is the service name to request
     `params' specifies additional parameters for negotiation.  It may be NULL
        to use default parameters.  This is automatically freed.
     `server_host_name' name to use for the server host when checking host key
     `key_check' is used to check the validity of the host key, if non-NULL.
                 This is also called during rekey, and thus data (and the
                 context) must remain valid for the duration of the connection.
     `key_context' is passed to the key_check callback.
     `version_callback' is version check function, or NULL
     `version_context' is given as argument to `version_callback'. */
SshStream ssh_transport_client_wrap(SshStream stream,
                                    SshRandomState random_state,
                                    const char *version,
                                    const char *service,
                                    SshTransportParams params,
                                    const char *server_host_name,
                                    SshKeyCheckCallback key_check,
                                    void *key_context,
                                    SshVersionCallback version_callback,
                                    void *version_context);

/* Takes a stream which is supposed to be a connection to the client,
   and performs server-side processing for the transport layer.  Returns
   a SshStream object representing the transport layer.
     `stream' is the connection to the client.  It will be automatically
        closed by the transport layer code.
     `random_state' is an initialized random state.  It is not automatically
        freed and can be shared with multiple protocol objects.
     `version' is the application version number (e.g. "2.0 rs6000-ibm-aix4.1")
     `params' specifies additional parameters for negotiation.  It may be
        NULL to use default parameters.
     `private_host_key' gives the private host key.  The key will be copied
       into the protocol object.
     `private_server_key' gives the private server key.  The key will be
       copied into the protocol object.  It may be NULL.
     `public_host_key_blob' gives the public host key to be passed to the
        other side.  This may include certificates.  It is copied into
        the protocol object.
     `version_callback' is version check function, or NULL
     `version_context' is given as argument to `version_callback'. */
SshStream ssh_transport_server_wrap(SshStream stream,
                                    SshRandomState random_state,
                                    const char *version,
                                    SshTransportParams params,
                                    SshPrivateKey private_host_key,
                                    SshPrivateKey private_server_key,
                                    const unsigned char *public_host_key_blob,
                                    unsigned int public_host_key_blob_len,
                                    SshVersionCallback version_callback,
                                    void *version_context);

typedef struct {
  /* XXX should use 64 bit type */
  unsigned long compressed_incoming_bytes;
  unsigned long uncompressed_incoming_bytes;
  unsigned long compressed_outgoing_bytes;
  unsigned long uncompressed_outgoing_bytes;
  unsigned long incoming_packets;
  unsigned long outgoing_packets;
} SshTransportStatistics;

/* Returns statistics information about the transport layer object. */
void ssh_transport_get_statistics(SshStream transport_stream,
                                  SshTransportStatistics *statistics_return);

/* compat flags structure. These are pointers, because these can only
   fetched before the transport stream is wrapped. Their values change
   during the kexinit phase. */
typedef struct 
{
  Boolean *publickey_draft_incompatility;
} *SshTransportCompat;

/* Return application level compatibility flags. Note that this must
   not be called if tr has become invalid for some reason. The return
   struct should be freed by the caller, when it is no longer
   needed. */
void ssh_transport_get_compatibility_flags(SshStream stream,
                                           SshTransportCompat *compat_flags);

#endif /* SSHTRANS_H */
