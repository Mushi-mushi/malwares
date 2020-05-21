/*

  sshauths.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH User authentication protocol, server-side.
                   
*/

#include "sshincludes.h"
#include "sshcross.h"
#include "sshbuffer.h"
#include "sshauth.h"
#include "sshmsgs.h"
#include "sshtimeouts.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "Ssh2AuthServer"

typedef struct {
  /* Cross-layer protocol context for the stream downwards. */
  SshCrossDown down;

  /* Cross-layer protocol context for the stream upwards. */
  SshStream up;
  
  /* The policy function.  This is always a valid policy function (if the
     application passed NULL, a default function will be used here). */
  SshAuthPolicyProc policy_proc;

  /* Context to pass to the policy function. */
  void *policy_context;
  
  /* Number of authentication methods supported. */
  unsigned int num_methods;

  /* Array defining the supported authentication methods. */
  const SshAuthServerMethod *methods;

  /* Context argument to pass to the authentication method functions. */
  void *method_context;

  /* If true, we are waiting for a continuation packet for an authentication
     method. */
  Boolean waiting_continuation;

  /* Number of the method that is active (valid only if waiting_continuation
     is TRUE). */
  int active_method_index;
  
  /* Places where the authentication methods can store data.  There is
     one element for each authentication method.  These are allocated
     with ssh_xmalloc. */
  void **state_placeholders;     /* array of num_methods elements */
  void **longtime_placeholders;  /* array of num_methods elements */
  
  /* Client host IP address, as a string (e.g., "121.23.125.98").
     This is allocated by ssh_xmalloc. */
  char *client_ip;

  /* Client-side port number, as a string (e.g., "1241").  This is
     allocated by ssh_xmalloc. */
  char *client_port;

  /* Length of the session id. */
  size_t session_id_len;

  /* The session id, from the startup packet.  This is allocated by ssh_xmalloc. */
  unsigned char *session_id;

  /* Copy of the startup packet received from the transport layer, or NULL
     if not yet received.  This is allocated by ssh_buffer_allocate. */
  SshBuffer *startup_packet;

  /* Copy of the last algorithms packet received from the transport layer,
     or NULL if not yet received.  This is allocated by ssh_buffer_allocate. */
  SshBuffer *algorithms_packet;
  
  /* The requested user name, or NULL if no requests have yet been received.
     This is allocated by ssh_xmalloc. */
  char *requested_user;

  /* The requested service name, or NULL if no requests have yet been
     received.  This is allocated by ssh_xmalloc. */
  char *requested_service;

  /* Comma-separated list of successfully performed authentications, or
     NULL if no authentications have yet been successfully performed.
     This is allocated by ssh_xmalloc. */
  char *successful_authentications;

  /* Comma-separated list of authentication methods that can purposefully
     continue authentication.  This is the list sent to the client in
     failure messages.  This is allocated by ssh_xmalloc. */
  char *continuations;
} *SshAuthServer;


/* Forward declarations. */
void ssh_auths_call_method(SshAuthServer auth, SshAuthServerOperation op,
                           const unsigned char *data, size_t len);


/* Sends a SSH_MSG_USERAUTH_FAILURE packet down (to the client). */

void ssh_auths_send_failure(SshAuthServer auth, Boolean partial_success)
{
  ssh_cross_down_send_encode(auth->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_USERAUTH_FAILURE,
                             SSH_FORMAT_UINT32_STR, 
                              auth->continuations, strlen(auth->continuations),
                             SSH_FORMAT_BOOLEAN, partial_success,
                             SSH_FORMAT_END);
}

/* Sends a disconnect packet and marks the protocol as dead. */

void ssh_auths_disconnect(SshAuthServer auth, const char *msg)
{
  /* Abort active authentication method if any. */
  if (auth->waiting_continuation)
    {
      ssh_auths_call_method(auth, SSH_AUTH_SERVER_OP_ABORT, NULL, 0);
      auth->waiting_continuation = FALSE;
    }

  /* Send the disconnect message and EOF down. */
  ssh_cross_down_send_disconnect(auth->down, TRUE,
                                 SSH_DISCONNECT_AUTHENTICATION_ERROR,
                                 "%s", msg);
  ssh_cross_down_send_eof(auth->down);

  /* Send the disconnect message and EOF up. */
  ssh_cross_up_send_disconnect(auth->up, TRUE,
                               SSH_DISCONNECT_AUTHENTICATION_ERROR,
                               "%s (user '%s', client address '%s:%s', "
                               "requested service '%s')", 
                               msg, auth->requested_user,
                               auth->client_ip,
                               auth->client_port,
                               auth->requested_service);

  ssh_cross_up_send_eof(auth->up);
}

/* Registers that the given authentication method has successfully completed
   for the current user.  Updates the authentications that can continue.
   Returns TRUE if no more authentications are required and authentication
   is now complete. */

Boolean ssh_auths_register_success(SshAuthServer auth, const char *method)
{
  char *cp;
  int len;

  /* Add the method to the list of successful authentications. */
  if (auth->successful_authentications == NULL)
    auth->successful_authentications = ssh_xstrdup(method);
  else
    {
      len = strlen(auth->successful_authentications) + 1 + strlen(method) + 1;
      cp = ssh_xmalloc(len);
      snprintf(cp, len, "%s,%s", auth->successful_authentications, method);
      ssh_xfree(auth->successful_authentications);
      auth->successful_authentications = cp;
    }

  /* Call the policy function to determine whether this is sufficient, and
     if not, which methods to suggest next. */
  cp = (*auth->policy_proc)(auth->requested_user, auth->requested_service,
                            auth->client_ip, auth->client_port,
                            auth->successful_authentications,
                            auth->policy_context);
  /* XXX should remove already completed methods? */
  if (auth->continuations)
    ssh_xfree(auth->continuations);
  auth->continuations = cp;

  /* Return TRUE if no more authentication is needed. */
  return cp == NULL;
}

/* Clears saved undo data for each authentication method.  Note that this
   also calls the function for those methods not called yet. */

void ssh_auths_clear_all_state(SshAuthServer auth,
                               SshAuthServerOperation op)
{
  int i;

  for (i = 0; i < auth->num_methods; i++)
    {
      auth->active_method_index = i;
      ssh_auths_call_method(auth, op, NULL, 0);
    }
}

/* This function is called when authentication has completed
   successfully.  This sends packets related to the success, and sets
   up shortcircuiting packets. */

void ssh_auths_success(SshAuthServer auth)
{
  /* Set status to successful (but drain pending output), and send
     SUCCESS packet. */
  SSH_DEBUG(6, ("success method = %s",
                auth->methods[auth->active_method_index].name));

  /* Clear longtime_placeholders. */
  ssh_auths_clear_all_state(auth,
                            SSH_AUTH_SERVER_OP_CLEAR_LONGTIME);

  /* Send SSH_MSG_USERAUTH_SUCCESS. */
  ssh_cross_down_send_encode(auth->down, SSH_CROSS_PACKET,
                             SSH_FORMAT_CHAR,
                             (unsigned int) SSH_MSG_USERAUTH_SUCCESS,
                             SSH_FORMAT_END);

  /* Send up the buffered STARTUP packet. */
  ssh_cross_up_send(auth->up, SSH_CROSS_STARTUP,
                    ssh_buffer_ptr(auth->startup_packet),
                    ssh_buffer_len(auth->startup_packet));

  /* Send up the buffered ALGORITHMS packet. */
  ssh_cross_up_send(auth->up, SSH_CROSS_ALGORITHMS,
                    ssh_buffer_ptr(auth->algorithms_packet),
                    ssh_buffer_len(auth->algorithms_packet));

  /* Send up an AUTHENTICATED packet. */
  ssh_cross_up_send_encode(auth->up, SSH_CROSS_AUTHENTICATED,
                           SSH_FORMAT_UINT32_STR,
                             auth->requested_user,
                             strlen(auth->requested_user),
                           SSH_FORMAT_UINT32_STR,
                             auth->requested_service,
                             strlen(auth->requested_service),
                           SSH_FORMAT_END);
  
  /* Shortcircuit communications between the up stream and the down stream.
     Functions in this module will no longer be called until the up stream
     is destroyed. */
  ssh_cross_shortcircuit(auth->up, auth->down);

  /* After this, none of our callbacks except destroy should get called. */
}

/* Calls the currently active authentication method with the current
   parameters, and updates state according to the return value from
   the authentication method.. */

void ssh_auths_call_method(SshAuthServer auth,
                           SshAuthServerOperation op,
                           const unsigned char *data, size_t len)
{
  int i;
  unsigned int packet_type;
  SshAuthServerResult result;
  SshBuffer *buffer;

  i = auth->active_method_index;

  /* Sanity checks... */
  assert(i >= 0 && i < auth->num_methods);
  assert(auth->requested_user != NULL);

  /* Save the data in a buffer. */
  buffer = ssh_buffer_allocate();
  ssh_buffer_append(buffer, data, len);
  
  /* Call the authentication method. */
  result = (*auth->methods[i].proc)(op, auth->requested_user, buffer,
                                    auth->session_id, auth->session_id_len,
                                    &auth->state_placeholders[i],
                                    &auth->longtime_placeholders[i],
                                    auth->method_context);

  /* Process the return value depending on the operation. */
  switch (op)
    {
    case SSH_AUTH_SERVER_OP_START:
    case SSH_AUTH_SERVER_OP_CONTINUE:
      switch (result)
        {
        case SSH_AUTH_SERVER_ACCEPTED:
          /* Authentication method was successful.  Should have no state
             left between packets. */
          assert(auth->state_placeholders[i] == NULL);
          
          /* Register the success, and determine what to do next. */
          if (ssh_auths_register_success(auth, auth->methods[i].name))
            {
              /* No more authentication is needed.  Authentication
                 successful. */
              ssh_auths_success(auth);
            }
          else
            {
              /* More authentications are needed. */
              SSH_DEBUG(6, ("call_method: More authentications needed."));
              auth->waiting_continuation = FALSE;
              ssh_auths_send_failure(auth, TRUE);
            }
          break;
          
        case SSH_AUTH_SERVER_REJECTED:
          /* This authentication method was rejected (but it might have
             had side-effects that were recorded in longtime_placeholder). */
          assert(auth->state_placeholders[i] == NULL);
          auth->waiting_continuation = FALSE;
          ssh_auths_send_failure(auth, FALSE);
          break;
      
        case SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED:
          /* This authentication method was rejected and cannot be 
             used again in this authentication.  This can be used
             for example in limiting login attempts. */
          assert(auth->state_placeholders[i] == NULL);
          auth->waiting_continuation = FALSE;
          ssh_auths_disconnect(auth, "Authentication method disabled."); 
          break;

        case SSH_AUTH_SERVER_REJECTED_WITH_PACKET_BACK:
          /* The authentication method wants to send out a packet, and then
             continue authentication with the same method. */
          auth->waiting_continuation = FALSE;
          /* Sanity check the outgoing packet. */

          if (ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                               SSH_FORMAT_CHAR, &packet_type,
                               SSH_FORMAT_END) == 0)
            ssh_fatal("ssh_auths_call_method: unable to decode the packet "
                      "type");

          if (packet_type < SSH_FIRST_USERAUTH_METHOD_PACKET ||
              packet_type > SSH_LAST_USERAUTH_METHOD_PACKET)
            ssh_fatal("ssh_auths_call_method: method sending bad packet "
                      "(1) %d",
                      (int)packet_type);
          /* Send the packet down. */
          ssh_cross_down_send(auth->down, SSH_CROSS_PACKET,
                              ssh_buffer_ptr(buffer), ssh_buffer_len(buffer));
          break;
      
        case SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK:
          /* The authentication method wants to send out a packet, and then
             continue authentication with the same method. */
          auth->waiting_continuation = TRUE;
       
          /* Sanity check the outgoing packet. */
          if (ssh_decode_array(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer),
                               SSH_FORMAT_CHAR, &packet_type,
                               SSH_FORMAT_END) == 0 ||
              packet_type < SSH_FIRST_USERAUTH_METHOD_PACKET ||
              packet_type > SSH_LAST_USERAUTH_METHOD_PACKET)
            ssh_fatal("ssh_auths_call_method: method sending bad packet"
                      "(2) %d",
                      (int)packet_type);
          /* Send the packet down. */
          ssh_cross_down_send(auth->down, SSH_CROSS_PACKET,
                              ssh_buffer_ptr(buffer), ssh_buffer_len(buffer));
          break;

        default:
          /* Unexpected result from method function. */
          ssh_fatal("ssh_auths_call_method: unknown result %d", (int)result);
        }
      break;

    case SSH_AUTH_SERVER_OP_ABORT:
      /* Aborted a continued authentication method.  Sanity check. */
      assert(auth->state_placeholders[i] == NULL);
      break;
    case SSH_AUTH_SERVER_OP_UNDO_LONGTIME:
      /* Aborted (undid) the entire authentication sequence.  Sanity check. */
      assert(auth->state_placeholders[i] == NULL);
      assert(auth->longtime_placeholders[i] == NULL);
      break;
    case SSH_AUTH_SERVER_OP_CLEAR_LONGTIME:
      /* Freed memory reserved for undo data. */
      assert(auth->state_placeholders[i] == NULL);
      assert(auth->longtime_placeholders[i] == NULL);
      break;
    default:
      /* Unknown operation. */
      ssh_fatal("ssh_auths_call_method: unknown op %d", (int)op);
    }

  /* Free the packet buffer. */
  ssh_buffer_free(buffer);
}

/* Processes an incoming packet from the transport layer stream.  `packet'
   should contain the payload of the packet (without any cross-layer
   headers).  This will consume data from the packet, but will not free it. */

void ssh_auths_process_request(SshAuthServer auth, const unsigned char *data,
                               size_t len)
{
  unsigned int packet_type;
  char *user, *service, *method;
  int i;
  size_t parsed_bytes;
  unsigned char ch;

  /* Decode the common part of the authentication request. */
  parsed_bytes = ssh_decode_array(data, len,
                                  SSH_FORMAT_CHAR, &packet_type,
                                  SSH_FORMAT_UINT32_STR, &user, NULL,
                                  SSH_FORMAT_UINT32_STR, &service, NULL,
                                  SSH_FORMAT_UINT32_STR, &method, NULL,
                                  SSH_FORMAT_END);
  if (parsed_bytes == 0)
    {
      ssh_auths_disconnect(auth, "Received bad authentication packet");
      return;
    }

  /* All packets we receive should be of type SSH_MSG_USERAUTH_REQUEST. */
  if (packet_type != SSH_MSG_USERAUTH_REQUEST)
    {
      ssh_xfree(user);
      ssh_xfree(service);
      ssh_xfree(method);
      ssh_auths_disconnect(auth, "Received bad authentication packet.");
      return;
    }

  if (strlen(user) > 64)
    {
      ssh_xfree(user);
      ssh_xfree(service);
      ssh_xfree(method);
      ssh_auths_disconnect(auth, "User name too long.");
      return;
    }
  for (i = 0; user[i]; i++)
    {
      ch = user[i];
      if (isalnum(ch))
        continue;
      if (ch == '-' || ch == '+' || ch == '_' || ch == '.')
        continue;
      if (ch >= 128) /* Assume 8-bit iso-latin characters. */
        continue;
      ssh_xfree(user);
      ssh_xfree(service);
      ssh_xfree(method);
      ssh_auths_disconnect(auth, "User name contains illegal characters.");
      return;
    }

  SSH_DEBUG(6, ("process_request: user %.20s service %.20s method %.20s",
                user, service, method));

  /* If the possible continuations haven't been computed yet, do it now. */
  if (auth->continuations == NULL)
    auth->continuations = (*auth->policy_proc)(user, service,
                                               auth->client_ip,
                                               auth->client_port,
                                               "",
                                               auth->policy_context);
  
  /* If continuing authentication and method is different, abort the old
     authentication method. */
  if (auth->waiting_continuation &&
      strcmp(auth->methods[auth->active_method_index].name, method) != 0)
    {
      SSH_DEBUG(6, ("process_request: cancelling old continued method"));
      ssh_auths_call_method(auth, SSH_AUTH_SERVER_OP_ABORT, NULL, 0);
      auth->waiting_continuation = FALSE;
    }
  
  /* If the user or service has changed, undo all side-effects by
     authentications and clear state to as if authentication was just
     starting. */
  if (auth->requested_user != NULL &&
      (strcmp(auth->requested_user, user) != 0 ||
       strcmp(auth->requested_service, service) != 0))
    {
      SSH_DEBUG(6, ("process_request: undoing old state"));
      ssh_auths_clear_all_state(auth, SSH_AUTH_SERVER_OP_UNDO_LONGTIME);
      if (auth->requested_user)
        {
          ssh_xfree(auth->requested_user);
          ssh_xfree(auth->requested_service);
          auth->requested_user = NULL;
          auth->requested_service = NULL;
        }
      /* Reset the possible continuations. */
      ssh_xfree(auth->continuations);
      auth->continuations = (*auth->policy_proc)(user, service,
                                                 auth->client_ip,
                                                 auth->client_port,
                                                 "",
                                                 auth->policy_context);
      if (auth->successful_authentications)
        {
          ssh_xfree(auth->successful_authentications);
          auth->successful_authentications = NULL;
        }
      assert(!auth->waiting_continuation);
    }

  /* Save user and service if not already saved. */
  if (auth->requested_user == NULL)
    {
      auth->requested_user = ssh_xstrdup(user);
      auth->requested_service = ssh_xstrdup(service);
    }

  /* Find the method. */
  auth->active_method_index = -1;
  for (i = 0; auth->methods[i].name != NULL; i++)
    if (strcmp(auth->methods[i].name, method) == 0)
      {
        auth->active_method_index = i;
        break;
      }

  /* Free the allocated strings. */
  ssh_xfree(service);
  ssh_xfree(user);
  ssh_xfree(method);

  /* If we don't have a valid method, return failure. */
  if (auth->active_method_index == -1)
    {
      ssh_auths_send_failure(auth, FALSE);
      return;
    }
  
  /* Process the authentication request. */
  if (auth->waiting_continuation)
    ssh_auths_call_method(auth, SSH_AUTH_SERVER_OP_CONTINUE,
                          data + parsed_bytes, len - parsed_bytes);
  else
    ssh_auths_call_method(auth, SSH_AUTH_SERVER_OP_START,
                          data + parsed_bytes, len - parsed_bytes);
}

/* Processes an incoming packet from the transport stream.  `type' is
   the type of the packet.  `packet' contains the body of the cross
   layer packet (the header has already been stripped). */

void ssh_auths_down_received_packet(SshCrossPacketType type,
                                    const unsigned char *data, size_t len,
                                    void *context)
{
  SshAuthServer auth = (SshAuthServer)context;
  char *service;
  
  switch (type)
    {
    case SSH_CROSS_PACKET:
      ssh_auths_process_request(auth, data, len);
      break;
      
    case SSH_CROSS_DISCONNECT:
      SSH_DEBUG(6, ("received_packet: DISCONNECT from transport code."));
      ssh_cross_up_send(auth->up, SSH_CROSS_DISCONNECT, data, len);
      ssh_cross_up_send_eof(auth->up);
      break;

    case SSH_CROSS_DEBUG:
      ssh_debug("Received DEBUG packet.");
      ssh_cross_up_send(auth->up, SSH_CROSS_DEBUG, data, len);
      break;
      
    case SSH_CROSS_STARTUP:
      /* Received a startup packet.  We save the entire packet for passing
         up later.  We also extract from the packet the fields that are
         relevant for authentication. */
      SSH_DEBUG(6, ("down_received_packet: Received STARTUP packet."));
      assert(auth->client_ip == NULL);
      auth->startup_packet = ssh_buffer_allocate();
      ssh_buffer_append(auth->startup_packet, data, len);
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           SSH_FORMAT_UINT32_STR, 
                             &auth->session_id, &auth->session_id_len,
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           SSH_FORMAT_UINT32_STR, &auth->client_ip, NULL,
                           SSH_FORMAT_UINT32_STR, &auth->client_port, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_auths_disconnect(auth, "Bad startup packet");
      break;
      
    case SSH_CROSS_ALGORITHMS:
      SSH_DEBUG(6, ("down_received_packet: Received ALGORITHMS packet."));
      if (auth->algorithms_packet == NULL)
        auth->algorithms_packet = ssh_buffer_allocate();
      else
        ssh_buffer_clear(auth->algorithms_packet);
      ssh_buffer_append(auth->algorithms_packet, data, len);
      break;

    case SSH_CROSS_SERVICE_REQUEST:
      SSH_DEBUG(6, ("down_received_packet: Received SERVICE_REQUEST packet."));
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &service, NULL,
                           SSH_FORMAT_END) == 0)
        {
          ssh_auths_disconnect(auth, "Bad service request packet");
          break;
        }
      if (strcmp(service, SSH_USERAUTH_SERVICE) == 0)
        ssh_cross_down_send(auth->down, SSH_CROSS_SERVICE_ACCEPT, NULL, 0);
      else
        ssh_auths_disconnect(auth, "Wrong service name.");
      break;

    default:
      ssh_debug("Received unknown cross packet %d", (int)type);
      ssh_auths_disconnect(auth, "Bad incoming cross packet");
    }
}

/* Called by the down stream implementation when an EOF is received from
   down.  The EOF is simply passed up. */

void ssh_auths_down_received_eof(void *context)
{
  SshAuthServer auth = (SshAuthServer)context;

  ssh_cross_up_send_eof(auth->up);
}

/* The upper stream has been closed.  We should destroy the down stream
   (after its buffers have drained) and free any allocated memory.  Any
   ongoing authentication state needs to be gracefully cleared. */

void ssh_auths_up_destroy(void *context)
{
  SshAuthServer auth = (SshAuthServer)context;

  /* Undo all already performed authentications (unless we haven't received
     any authentication packets yet). */
  if (auth->requested_user != NULL)
    ssh_auths_clear_all_state(auth, SSH_AUTH_SERVER_OP_UNDO_LONGTIME);
  
  /* Destroy the downward stream.  Note that its buffers will automatically
     drain before it is actually destroyed. */
  ssh_cross_down_destroy(auth->down);

  /* Free any memory. */
  ssh_xfree(auth->state_placeholders);
  ssh_xfree(auth->longtime_placeholders);
  if (auth->client_ip)
    ssh_xfree(auth->client_ip);
  if (auth->client_port)
    ssh_xfree(auth->client_port);
  if (auth->session_id)
    ssh_xfree(auth->session_id);
  if (auth->startup_packet)
    ssh_buffer_free(auth->startup_packet);
  if (auth->algorithms_packet)
    ssh_buffer_free(auth->algorithms_packet);
  if (auth->requested_user)
    ssh_xfree(auth->requested_user);
  if (auth->requested_service)
    ssh_xfree(auth->requested_service);
  if (auth->successful_authentications)
    ssh_xfree(auth->successful_authentications);
  if (auth->continuations)
    ssh_xfree(auth->continuations);

  /* Fill with known "garbage" value to ease debugging. */
  memset(auth, 'F', sizeof(*auth));
  ssh_xfree(auth);
}

/* This is the default policy procedure that is used if NULL is supplied as
   the policy function.  The context points to the SshAuthServer object. */

char *ssh_auths_default_policy_proc(const char *user, const char *service,
                                    const char *client_ip,
                                    const char *client_port,
                                    const char *completed,
                                    void *context)
{
  SshAuthServer auth = (SshAuthServer)context;
  SshBuffer buffer;
  char *cp;
  int i;

  SSH_DEBUG(6, ("default_policy_proc: user '%s' client_ip '%s' completed '%s'",
                user, client_ip, completed));

  /* If we have successfully completed some authentication, allow the user
     in. */
  if (completed != NULL)
    if (strlen(completed) > 0)
      return NULL;

  /* Otherwise, construct a list of the authentications that can continue.
     All supported authentication methods are included in the list. */

  ssh_buffer_init(&buffer);
  for (i = 0; i < auth->num_methods; i++)
    {
      if (i > 0)
        ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
      ssh_buffer_append(&buffer, (unsigned char *) auth->methods[i].name,
                    strlen(auth->methods[i].name));
    }
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  cp = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);

  SSH_DEBUG(6, ("default_policy_proc output: %s", cp));

  return cp;
}

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

   Once authentication is complete, this will pass up the original
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
     `transport'            transport layer stream
     `policy_proc'          function to control authentication policy
                            (may be NULL, in which case each method in
                            the array is individually acceptable)
     `policy_context'       passed to the policy function
     `methods'              array of supported methods, terminated by
                            an element with NULL name.  This needs to stay
                            valid until the stream is destroyed.
     `method_context'       context to pass to methods (normally NULL) */

SshStream ssh_auth_server_wrap(SshStream transport,
                               SshAuthPolicyProc policy_proc,
                               void *policy_context,
                               const SshAuthServerMethod *methods,
                               void *method_context)
{
  SshAuthServer auth;
  int num_methods;

  /* Count the number of authentication methods avaialable. */
  for (num_methods = 0; methods[num_methods].name; num_methods++)
    ;
  
  /* Allocate and initialize memory. */
  auth = ssh_xcalloc(sizeof(*auth), 1);
  auth->down = ssh_cross_down_create(transport,
                                     ssh_auths_down_received_packet,
                                     ssh_auths_down_received_eof,
                                     NULL, (void *)auth);
  auth->up = ssh_cross_up_create(NULL, NULL, NULL,
                                 ssh_auths_up_destroy,
                                 (void *)auth);
  auth->waiting_continuation = FALSE;
  auth->active_method_index = -1;
  if (policy_proc == NULL)
    {
      /* Use default policy proc if the user supplied NULL. */
      policy_proc = ssh_auths_default_policy_proc;
      policy_context = (void *)auth;
    }
  auth->policy_proc = policy_proc;
  auth->policy_context = policy_context;
  auth->num_methods = num_methods;
  auth->methods = methods;
  auth->method_context = method_context;
  auth->state_placeholders = ssh_xcalloc(num_methods, sizeof(void *));
  auth->longtime_placeholders = ssh_xcalloc(num_methods, sizeof(void *));
  auth->client_ip = NULL;
  auth->client_port = NULL;
  auth->session_id_len = 0;
  auth->session_id = NULL;
  auth->startup_packet = NULL;
  auth->algorithms_packet = NULL;
  auth->requested_user = NULL;
  auth->requested_service = NULL;
  auth->successful_authentications = NULL;
  auth->continuations = NULL;

  /* Start receiving packets from the down stream. */
  ssh_cross_down_can_receive(auth->down, TRUE);

  /* Return the up stream. */
  return auth->up;
}

#if 0
XXX check what happens if you shortcircuit after up or down has received eof.
    Should forward eof to other side automatically?;
XXX check can_receive vs. shortcircuit;
#endif

/* XXX timeout in which authentication must be performed */
