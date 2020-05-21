/*

  sshauth.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH User Authentication Protocol interface.

*/

/*
 * $Id: sshauth.h,v 1.9 1998/07/11 12:37:00 tri Exp $
 * $Log: sshauth.h,v $
 * $EndLog$
 */



#ifndef SSHAUTH_H
#define SSHAUTH_H

#include "sshstream.h"
#include "sshcross.h"

#define SSH_USERAUTH_SERVICE  "ssh-userauth"

/************************** server side ****************************/

/* This function is used to access the authentication policy for the
   current system.  It is supposed to return a comma-reparated list
   of authentication methods that can follow.  An empty list indicates
   that no authentications are useful, and NULL means to allow the user
   to log in.
     `user'        user name from the authentication request
     `service'     service name from the authentication request
     `client_ip'   IP address of client host, e.g. "121.34.100.5"
     `client_port' port number at client, e.g. "2507"
     `completed_authentications' comma-separated list of successfully
                   executed authentication methods for this user/service
     `context'     arbitrary context pointer
   The returned string should be allocated by ssh_xmalloc, and the caller
   must free the string when no longer needed. */
typedef char *(*SshAuthPolicyProc)(const char *user,
				   const char *service,
				   const char *client_ip,
				   const char *client_port,
				   const char *completed_authentications,
				   void *context);

/* Return code from an authentication method. */
typedef enum {
  /* The authentication request was accepted.  Note that the protocol
     code may sometimes require several different authentication
     methods to be accepted if required by the policy. */
  SSH_AUTH_SERVER_ACCEPTED,

  /* The authentication request was rejected. */
  SSH_AUTH_SERVER_REJECTED,

  /* The authentication request was rejected and method disabled. */
  SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED,

  /* The authentication request was rejected, but a special message
     should be sent back instead of the normal
     SSH_MSG_USERAUTH_FAILURE response.  This is used e.g. when
     probing whether a public key would be acceptable.  The authentication
     method must have replaced the packet in the buffer by the complete
     payload of a packet to be sent back to the client.  The packet to be
     sent back must have a packet number in the range 35...39. */
  SSH_AUTH_SERVER_REJECTED_WITH_PACKET_BACK,

  /* The authentication request is incomplete.  A packet should be
     sent back to the client, and authentication will continue if the
     client sends back a new packet with the appropriate response.
     The authentication method should replace the data in the buffer
     by the complete payload of the packet to send back (it must have
     a packet number in the range 35...39).  The method can use
     *state_placeholder to keep its internal state.  If a packet is
     received from the client with the number in the 35...39 range, it
     is passed to the same method with SSH_AUTH_SERVER_OP_CONTINUE
     operation.  If any other packet number or a new authentication
     request is received from the client, the method will be called
     with SSH_AUTH_SERVER_OP_ABORT before processing the other
     request; in this case the method should free any data stored at
     *state_placeholder. */
  SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK
} SshAuthServerResult;

/* Operation code for the authentication method. */
typedef enum {
  /* A new authentication request is being processed.
     *state_placeholder has been initialized to NULL.  packet_type is
     SSH_MSG_USERAUTH_REQUEST.  `packet' contains the fields of the
     original request packet except packet type, user name, and
     service name have already been stripped. */
  SSH_AUTH_SERVER_OP_START,

  /* Abort any intermediate authentication, and free any data stored
     at *state_placeholder.  This is guaranteed to be called if and
     only if the method has previously returned
     SSH_AUTH_CONTINUES_WITH_PACKET_BACK and another method is then
     requested or the client responds with an illegal packet
     number. */
  SSH_AUTH_SERVER_OP_ABORT,

  /* Continues authentication with a new packet from the client.  The
     packet type must be SSH_MSG_USERAUTH_REQUEST, and the method name
     must be the same as in the previous packet.  The method-specific
     part will be passed to the function in `packet'.
     `*state_placeholder' will contain the same value as when the
     method previously returned.  This is guaranteed to be called only
     if the method has previously returned
     SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK. */
  SSH_AUTH_SERVER_OP_CONTINUE,

  /* Undoes any side-effects by previous calls to this function.  This
     is called for all attempted authentications after if the user
     name or service changes.  This must return side-effects to the
     state they would have if the authentication had never been tried.
     This may use `longtime_placeholder' to store information needed
     for the undo.  This may be called even if the method has not been
     used; in that case, longtime_placeholder will be NULL.  The
     return value is ignored. */
  SSH_AUTH_SERVER_OP_UNDO_LONGTIME,

  /* Clears any saved state in `longtime_placeholder'.  This is called
     for all authentication methods after the authentication has
     completed successfully.  This should not undo side-effects.  This
     may be called even if the method has never been used; in that
     case, longtime_placeholder will be NULL.  The return value is
     ignored. */
  SSH_AUTH_SERVER_OP_CLEAR_LONGTIME
} SshAuthServerOperation;

/* Function used to represent an authentication method.  This function
   performs all processing by the authentication method.  An authentication
   method is policy-independent.
     `user'         user name from the (original) authentication request
     `packet'       method-specific remaining part of the packet
     `session_id'   session identifier
     `session_id_len' length of session identifier
     `state_placeholder' place to store context data between packets
     `longtime_placeholder'  can hold data between authentications
     		    (this is per-method)
     `method_context'   passed to the method function */
typedef SshAuthServerResult (*SshAuthServerMethodProc)(
        				SshAuthServerOperation op,
					const char *user,
					SshBuffer *packet,
					const unsigned char *session_id,
					size_t session_id_len,
					void **state_placeholder,
					void **longtime_placeholder,
					void *method_context);

/* This structure completely describes an authentication method.  All methods
   supported by an implementation are described by an array of these.
   The "none" method should not be listed in the array.  The array is
   terminated with an entry with NULL name. */
typedef struct SshAuthServerMethodRec {
  const char *name;		/* method name, e.g. "password" */
  SshAuthServerMethodProc proc;	/* function to perform authentication */
} SshAuthServerMethod;

/* Wraps the transport layer stream into an authentication stream.  This will
   use the given policy function to decide which authentication methods are
   acceptable, and the methods array to access individual authentication
   methods.  The stream will be closed automatically when the authentication
   stream is destroyed.

   Note that the protocol code is completely independent of any authentication
   methods, and does not implement any methods on its own (except the "none"
   method).  The protocol code takes care of interfacing and bookkeeping
   for interfacing the policy with policy-independent authentication methods.

   The returned stream speaks upwards the same cross layer protocol as
   the transport layer, and will pass any normal packets and disconnects
   through transparently (after authentication is complete; this does not
   talk at all with anything above this until authentication has completed).

   One authentication is complete, this will pass up the original
   SSH_CROSS_STARTUP, SSH_CROSS_ALGORITHMS packets, and
   will generate an SSH_CROSS_AUTHENTICATED packet (with the
   user name and service name specified in the authentication
   request).

   This will automatically respond to an
   SSH_CROSS_SERVICE_REQUEST packet by
   SSH_CROSS_SERVICE_ACCEPT if the service name is
   "ssh-userauth".  Otherwise, this will respond by sending a
   disconnect message.

   This will also pass through any SSH_CROSS_REKEY_REQUEST
   messages and SSH_CROSS_ALGORITHMS messages that are due to
   rekeys.

   The arguments are as follows:
     `transport_stream'     transport layer stream
     `policy_proc'          function to control authentication policy
                            (may be NULL, in which case each method in
			    the array is individually acceptable)
     `policy_context'       passed to the policy function
     `methods'              array of supported methods, terminated by
     			    an element with NULL name.  This needs to stay
			    valid until the stream is destroyed.
     `method_context'       context to pass to methods (normally NULL) */
SshStream ssh_auth_server_wrap(SshStream transport_stream,
			       SshAuthPolicyProc policy_proc,
			       void *policy_context,
			       const SshAuthServerMethod methods[],
			       void *method_context);

/************************** client side ****************************/

typedef enum {
  /* The protocol code calls this method to start authentication.
     This should call completion_proc when done (either during this
     call or later).  The protocol code will not free itself until
     this has been called.

     When the completion proc is called, if `result' is
     SSH_AUTH_CLIENT_FAIL, all other fields are ignored.  This
     indicates that the called method is not available at this time
     (e.g., the user has no suitable key for authentication).

     If `result' is SSH_AUTH_CLIENT_SEND, `user' should contain the user
     name to authenticate as, and `packet' should contain the
     method-dependent part of a SSH_MSG_USERAUTH_REQUEST packet (i.e.,
     the part after user name).  `packet' can also be NULL in which
     case it is assumed there is no method-specific data.  The
     protocol code will copy the user name, and will construct a
     suitable packet and send it to the server.  It will not call the
     same method again if authentication is successful.  The `packet'
     buffer should be allocated with ssh_buffer_allocate, and will be freed
     automatically by the generic code.

     If `result' is SSH_AUTH_CLIENT_SEND_AND_CONTINUE, `user' and
     `packet' are processed as in the previous case.  However,
     authentication is assumed to continue with further packets.
     These packets will be passed back to the same function, with
     SSH_AUTH_CLIENT_OP_CONTINUE as the operation, the packet type in
     `packet_type', and the remaining data in `packet_in'.  The
     function may examine and clear the packet, but should not free
     it.  It should then call the completion procedure again.
     `*state_placeholder' may be used to store data between packets.
     It should be cleared before calling the completion proc with
     SSH_AUTH_CLIENT_SEND or SSH_AUTH_CLIENT_FAIL.  If the server
     responds with success or failure before any other packet is received,
     this will be called with SSH_AUTH_OP_ABORT, which should clear any
     saved state from `*state_placeholder'. */
  SSH_AUTH_CLIENT_OP_START,

  /* Like SSH_AUTH_CLIENT_OP_START, but this should return SSH_AUTH_CLIENT_FAIL
     if the operation cannot be performed without user interaction or if
     it would require excessive computation.  This is called for all
     methods when started to attempt easy non-interactive authentications
     first before doing anything that requires user intervention.  When this
     operation is requested, the completion proc must be called during
     this call. */
  SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE,
  
  /* This operation indicates that we are actually continuing a previous
     authentication attempt with this method, and `packet_type' and
     `packet_in' contain the type and contents of the received packet.
     This is only called after returning SSH_AUTH_CLIENT_SEND_AND_CONTINUE.
     The caller will free `packet_in' after this has returned. */
  SSH_AUTH_CLIENT_OP_CONTINUE,

  /* This operation indicates that a continued authentication attempt should
     be aborted.  Any dialogs that might be up should be closed, and
     saved state in `*state_placeholder' must be cleared.
     If this operation is called while an authentication method is in
     progress, the implementation must still wait for the completion
     procedure to be called before freeing the stream (thus, this is
     allowed to skip e.g. closing the dialog).

     The completion procedure should *not* be called for this operation;
     this operation is required to complete immediately. */
  SSH_AUTH_CLIENT_OP_ABORT
} SshAuthClientOperation;

typedef enum {
  /* This value should be returned if the requested authentication method
     is not currently available and no request packet should be sent for
     it. */
  SSH_AUTH_CLIENT_FAIL,

  /* This value indicates that the user has requested to abort authentication
     entirely.  If this is returned, the connection will be closed,
     authentication terminates, and EOF will be returned from the
     returned authentication stream. */
  SSH_AUTH_CLIENT_CANCEL,

  /* Indicates that the client has prepared method-specific data in
     `packet' (or it can be NULL if there is no method-specific data),
     and an authentication request packet should be sent to the other side. */
  SSH_AUTH_CLIENT_SEND,

  /* Like above, but the method expects to receive additional packets back
     from the server.  Those packets will be directed to the same method
     with the SSH_AUTH_CLIENT_OP_CONTINUE operation. */
  SSH_AUTH_CLIENT_SEND_AND_CONTINUE,

  /* Like above, but the method does not terminate upon 
     SSH_MSG_USERAUTH_FAILURE or SSH_MSG_USERAUTH_SUCCESS. These messages
     should be passed to the method. */
  SSH_AUTH_CLIENT_SEND_AND_CONTINUE_MULTIPLE

} SshAuthClientResult;

/* A function of this type is passed as argument to the client-side
   authentication method.  The method should call this function when
   it is done for now.  See the definition of result codes for more info.
      `result'    result code
      `user'      user name to authenticate with (copied)
      `packet'    method-specific part of SSH_MSG_USERAUTH_REQUEST,
      		  or NULL if empty
      `completion_context'  context from the call
   This does not free the packet; data is copied from there to internal
   buffers during the call. */
typedef void (*SshAuthClientCompletionProc)(SshAuthClientResult result,
					    const char *user,
					    SshBuffer *packet,
					    void *completion_context);

/* Functions of this type represent authentication methods on the client
   side.  The generic code calls these to test if the method is currently
   available, to construct authentication requests, and to process
   continuation packets for an authentication method.  See the definition
   of the operations for more info.
     `op'            operation to be performed
     `user'          previous username (or same as in first packet); will
                     remain valid until completion proc called
     `packet_type'   packet type if SSH_AUTH_CLIENT_OP_CONTINUE
     `packet_in'     rest of packet if SSH_AUTH_CLIENT_OP_CONTINUE or NULL
     `state_placeholder' place to store data between packets
     `completion_proc'  must be called to return status from the method
     `completion_context'  must be passed to the completion proc
     `method_context' context from the method array
   Note that it is essential that this calls the completion proc either
   immediately or some time after returning.  Otherwise, the protocol
   code will hang and not be freed.  The completion procedure is not
   called for SSH_AUTH_CLIENT_OP_ABORT, however. */
typedef void (*SshAuthClientMethodProc)(
		    SshAuthClientOperation op,
		    const char *user,
		    unsigned int packet_type,
		    SshBuffer *packet_in,
		    const unsigned char *session_id,
		    size_t session_id_len,
		    void **state_placeholder,
		    SshAuthClientCompletionProc completion_proc,
		    void *completion_context,
		    void *method_context);

/* This structure completely describes an authentication method for
   the client side.  All methods supported by an implementation are
   described by an array of these.  The "none" method should not be
   listed in the array.  The array is terminated with an entry with
   NULL name. */
typedef struct SshAuthClientMethodRec {
  const char *name;		/* method name, e.g. "password" */
  SshAuthClientMethodProc proc;	/* function to perform authentication */
} SshAuthClientMethod;

/* Wraps the transport layer stream into an authentication stream.  This
   will automatically handle the entire authentication dialog, and will
   call the listed authentication methods as supported by the server
   to perform authentication.

   The authentication stream talks the cross layer protocol.  It will
   immediately pass up any SSH_CROSS_STARTUP and
   SSH_CROSS_ALGORITHMS packets, but will not communicate other
   data until authentication is complete.
   SSH_CROSS_AUTHENTICATED (with the user name and service name)
   will be sent up the stream when authentication has been
   successfully completed.  If authentication fails, EOF will be
   received from the stream.

   It is legal to destroy the stream at any time.  If destroyed while an
   authentication method is active, the completion context for the
   authentication method will remain valid until called, and then all
   active methods will be aborted.  In most cases, the most natural method
   to abort authentication is to return SSH_AUTH_CLIENT_CANCEL rather than
   forcibly closing the stream, but both should work ok.
     `transport_stream'    the transport layer stream
     `service'             service name to request
     `methods'             array of supported authentication methods,
     			   ordered the preferred one first.  The array
			   terminates with a NULL method name.
     `method_context'      context to pass to methods (normally NULL) */
SshStream ssh_auth_client_wrap(SshStream transport_stream,
			       const char *initial_user,
			       const char *service,
			       const SshAuthClientMethod methods[],
			       void *method_context);

#endif /* SSHTRANS_H */
