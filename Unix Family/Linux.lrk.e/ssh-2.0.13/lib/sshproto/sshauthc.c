/*

sshauthc.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH User Authentication Protocol, client side.
                   
*/

#include "sshincludes.h"
#include "sshauth.h"
#include "sshmsgs.h"
#include "namelist.h"
#include "sshencode.h"
#include "sshcross.h"

#define SSH_DEBUG_MODULE "Ssh2AuthClient"

/* Client states. */

typedef enum {
  /* We are waiting for a startup message.  Authentication has not yet
     started. */
  SSH_AUTHC_WAITING_STARTUP,

  /* We are sending authentication requests or waiting for response to
     them.  */
  SSH_AUTHC_AUTHENTICATING,

  /* We are authenticating, but have sent a request for which we are expecting
     a continuation packet.  Valid responses from the server are continuation
     packets, SSH_MSG_USERAUTH_FAILURE and SSH_MSG_USERAUTH_SUCCESS (and
     SSH_MSG_USERAUTH_BANNER). */
  SSH_AUTHC_WAITING_CONTINUATION,

  /* We are are expecting a continuation packet. SSH_MSG_USERAUTH_FAILURE
     and SSH_MSG_USERAUTH_SUCCESS do not terminate authentication, but
     are passed to the authentication method. */
  SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE,

  /* We are aborting an authentication method.  The completion procedure
     should not get called in this state. */
  SSH_AUTHC_ABORTING,

  /* The user has been authenticated.  In this state, all data will be
     shortcircuited through this protocol level. */
  SSH_AUTHC_AUTHENTICATED,

  /* The protocol is dead.  We've sent a disconnect, and will not do any
     more operations. */
  SSH_AUTHC_DEAD
} SshAuthClientState;

typedef struct SshAuthClientRec {
  /* State of the protocol. */
  SshAuthClientState state;

  /* Index of the currently active method, or -1 if no method is active.
     This is always valid, but has a value != -1 only when state is
     SSH_AUTHC_WAITING_CONTINUATION or 
     SSH_AUTHC_WAITING_CONTINATION_MULTIPLE. */
  int active_method_index;

  /* This flag is true if we are currently starting a new method.  This is
     used to avoid potential infinite recursion when all productive methods
     immediately call the completion procedure with FAIL. */
  Boolean starting_next_method;

  /* This flag is set whenever recursion was attempted when starting the
     next method.  This will trigger looping. */
  Boolean next_method_recursed;

  /* The stream and related buffers going up.  Note that we know that it's
     an SshCrossUpStream, and call special functions for it. */
  SshStream up;

  /* The stream and related buffers going down. */
  SshCrossDown down;

  /* The user we are authenticating as.  Authentication methods may change
     the user.  The string is allocated with ssh_xmalloc. */
  char *user;

  /* The service we are requesting on the server.  The service may change,
     though this implementation does not allow it to change.  The string
     is allocated with ssh_xmalloc. */
  char *service;

  /* The session id and its length.  The session id is allocated with
     ssh_xmalloc. */
  unsigned char *session_id;
  size_t session_id_len;
  
  /* The available authentication methods, and their number.  The array points
     directly to user-supplied data. */
  const SshAuthClientMethod *methods;
  unsigned int num_methods;

  /* Context argument to be passed to all methods. */
  void *method_context;

  /* Comma-separated list of all supported method names.  The string is
     allocated by ssh_xmalloc. */
  char *methods_string;

  /* Array of void pointers to hold authentication method state between
     packets.  There's one element for each method (num_methods entries).
     The array is allocated by ssh_xmalloc; individual methods are responsible
     for allocating and freeing the data. */
  void **state_placeholders;

  /* Number of sent authentication requests for which we haven't
     received a reply yet. */
  unsigned int waiting_response_count;

  /* Comma-separated list of authentication methods that may
     productively continue authentication.  This is copied from the
     server's SSH_MSG_USERAUTH_FAILURE message, and already has
     unsupported methods stripped out.  The string is allocated with
     ssh_xmalloc.  It may be NULL if no productive methods are
     available. */
  char *productive_methods;

  /* Index to the productive methods list.  0 means to try the first method
     next, 1 to try the second method next, etc. */
  int productive_method_index;
} *SshAuthClient;

/* Forward declarations. */
void ssh_authc_start_next_method(SshAuthClient auth);


/* Sends a disconnect message both up and down.  This will presumably cause
   the upper level to destroy the upper stream, which will cause this protocol
   context to be terminated.  This effectively terminates the protocol and
   puts it in an inoperative state. */

void ssh_authc_both_disconnect(SshAuthClient auth, const char *message)
{
  SSH_DEBUG(6, ("disconnect: %.100s", message));
  ssh_cross_up_send_disconnect(auth->up, TRUE,
                               SSH_DISCONNECT_AUTHENTICATION_ERROR,
                               "%.500s", message);
  ssh_cross_down_send_disconnect(auth->down, TRUE,
                                 SSH_DISCONNECT_AUTHENTICATION_ERROR,
                                 "%.500s", message);
  /* Mark the protocol as dead, mark that we cannot receive more packets from
     either direction, and send EOF in both directions (after the disconnect
     packet). */
  auth->state = SSH_AUTHC_DEAD;
  ssh_cross_up_can_receive(auth->up, FALSE);
  ssh_cross_up_send_eof(auth->up);
  ssh_cross_down_can_receive(auth->down, FALSE);
  ssh_cross_down_send_eof(auth->down);
  /* Note that we didn't explicitly cancel authentication methods here;
     the upper level will presumably destroy us soon, and any active methods
     will be aborted at that time. */
}

/* Processes an EOF received from up.  This should normally not happen;
   presumably the upper level is aborting and will call destroy soon.  We'll
   just pass the EOF down. */

void ssh_authc_up_received_eof(void *context)
{
  SshAuthClient auth = (SshAuthClient)context;

  /* Pass the EOF down.  Presumably we'll either receive EOF back from down
     soon, or the upper level will destroy us. */
  ssh_cross_down_send_eof(auth->down);
}

/* The upper level is destroying the stream.  Abort any active authentication
   methods, and close the downward stream, and free all data. */

void ssh_authc_up_destroy(void *context)
{
  SshAuthClient auth = (SshAuthClient)context;
  int i;

  /* If a method is active, abort it now. */
  i = auth->active_method_index;
  if (i != -1)
    (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_ABORT, auth->user, 0, NULL,
                             auth->session_id, auth->session_id_len,
                             &auth->state_placeholders[i], NULL, NULL,
                             auth->method_context);

  /* Destroy the stream going down.  Note that it will not actually
     destroy itself until its internal buffers have been drained. 
     The stream going up will automatically destroy itself after having
     notified of the destruction by this callback. */
  ssh_cross_down_destroy(auth->down);

  /* Free any cached data. */
  if (auth->user)
    ssh_xfree(auth->user);
  if (auth->service)
    ssh_xfree(auth->service);
  if (auth->methods_string)
    ssh_xfree(auth->methods_string);
  if (auth->state_placeholders)
    ssh_xfree(auth->state_placeholders);
  if (auth->productive_methods)
    ssh_xfree(auth->productive_methods);

  /* Fill the context with garbage to ease trapping accesses after freeing, 
     and then free it. */
  memset(auth, 'F', sizeof(*auth));
  ssh_xfree(auth);
}

/* This is called when a SSH_MSG_USERAUTH_SUCCESS message is received from
   the remote host.  This will send the authenticated message up, and arrange
   to shortcircuit any packet between up and down to go directly to each
   other. */

void ssh_authc_process_success(SshAuthClient auth)
{
  SSH_DEBUG(6, ("success"));

  /* Mark that authentication is complete. */
  auth->state = SSH_AUTHC_AUTHENTICATED;

  /* Send the SSH_CROSS_AUTHENTICATED packet up. */
  ssh_cross_up_send_encode(auth->up, SSH_CROSS_AUTHENTICATED,
                           SSH_FORMAT_UINT32_STR, 
                             auth->user, strlen(auth->user), 
                           SSH_FORMAT_UINT32_STR,
                             auth->service, strlen(auth->service), 
                           SSH_FORMAT_END);

  /* Shortcircuit data between the upper and lower streams. */
  ssh_cross_shortcircuit(auth->up, auth->down);

  /* After this, none of our callbacks except destroy should get called. */
}

/* This function is passed as the completion procedure to
   authentication methods.  The methods call this when they are done.
     `result' indicates the operation to perform (see sshauth.h).
     `user' is the user name
     `packet' contains the method-specific part of the 
        SSH_MSG_USERAUTH_REQUEST packet.  It must be freed by caller.
     `completion_context' points to the SshAuthClient structure.
    Depending on `result', this may send the authentication packet,
    start the next method, or arrange to wait for reply to a packet. */

void ssh_authc_completion_proc(SshAuthClientResult result,
                               const char *user,
                               SshBuffer *packet,
                               void *completion_context)
{
  SshAuthClient auth = (SshAuthClient)completion_context;
  char *user_copy;
  int i;

  /* If DEAD, ignore all calls to this.  We are basically waiting for the
     upper level to destroy us. */
  if (auth->state == SSH_AUTHC_DEAD)
    return;

  /* The completion procedure should not get called when aborting... */
  if (auth->state == SSH_AUTHC_ABORTING)
    ssh_fatal("ssh_authc_completion_proc: called during ABORT "
              "(bug in authentication method '%s' implementation)",
              auth->methods[auth->active_method_index].name);

  /* Free the old saved user, and save the new user name.  Note that
     we copy before freeing, as user might actually be auth->user. */
  user_copy = ssh_xstrdup(user);
  if (auth->user)
    ssh_xfree(auth->user);
  auth->user = user_copy;

  /* Use the result code to decide what to do. */
  i = auth->active_method_index;
  switch (result)
    {
    case SSH_AUTH_CLIENT_FAIL:
      auth->active_method_index = -1;

      /* Sanity check: the method should not have left any data. */
      assert(auth->state_placeholders[i] == NULL);
      
      /* Start the next method. */
      ssh_authc_start_next_method(auth);
      break;

    case SSH_AUTH_CLIENT_CANCEL:
      /* Abort the entire authentication process.  Return EOF from the
         upper stream. */

      /* Sanity check: the method should not have left any data. */
      assert(auth->state_placeholders[i] == NULL);

      /* Send a disconnect message both ways. */
      ssh_authc_both_disconnect(auth, "Authentication cancelled by user.");
      break;

    case SSH_AUTH_CLIENT_SEND:
      /* The authentication method is to be attempted.  `packet' contains
         the method-dependent part of the packet to send. */

      /* Sanity check: the method should not have left any data.  However,
         when "none" request is sent, active_method_index will be -1. */
      assert(i == -1 || auth->state_placeholders[i] == NULL);

      assert(auth->state == SSH_AUTHC_AUTHENTICATING ||
             auth->state == SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE);
      auth->active_method_index = -1;

      /* Send a SSH_MSG_USERAUTH_REQUEST to the other side. */
      ssh_cross_down_send_encode(auth->down, SSH_CROSS_PACKET,
                                 SSH_FORMAT_CHAR,
                                 (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                 SSH_FORMAT_UINT32_STR,
                                   auth->user, strlen(auth->user),
                                 SSH_FORMAT_UINT32_STR,
                                   auth->service, strlen(auth->service), 
                                 SSH_FORMAT_UINT32_STR,
                                   (i == -1 ? "none" : auth->methods[i].name),
                                   strlen(i == -1 ? "none" :
                                          auth->methods[i].name),
                                 SSH_FORMAT_DATA,
                                   packet ? ssh_buffer_ptr(packet) : NULL,
                                   packet ? ssh_buffer_len(packet) : 0,
                                 SSH_FORMAT_END);

      /* Mark that we have one more request out waiting for reply. */
      auth->waiting_response_count++;
      break;
      
    case SSH_AUTH_CLIENT_SEND_AND_CONTINUE:
      /* The authentication method is to be attempted, and it expects
         to get a response packet from the server.  `packet' contains
         the method-dependent part of the packet to send. */
      assert(auth->state == SSH_AUTHC_AUTHENTICATING ||
             auth->state == SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE);

      /* Get the method index.  Note that here we leave the method index
         valid and set status to indicate continuation. */
      auth->state = SSH_AUTHC_WAITING_CONTINUATION;

      /* Send an authentication request to the other side. */
      ssh_cross_down_send_encode(auth->down, SSH_CROSS_PACKET,
                                 SSH_FORMAT_CHAR,
                                 (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                 SSH_FORMAT_UINT32_STR,
                                   auth->user, strlen(auth->user), 
                                 SSH_FORMAT_UINT32_STR,
                                   auth->service, strlen(auth->service), 
                                 SSH_FORMAT_UINT32_STR,
                                   auth->methods[i].name,
                                   strlen(auth->methods[i].name),
                                 SSH_FORMAT_DATA,
                                   ssh_buffer_ptr(packet),
                                   ssh_buffer_len(packet),
                                 SSH_FORMAT_END);

      /* Mark that we have one more request out waiting for reply. */
      auth->waiting_response_count++;
      break;
      

    case SSH_AUTH_CLIENT_SEND_AND_CONTINUE_MULTIPLE:
      /* Expecting response from the server. Even SSH_MSG_USERAUTH_FAILURE 
         and SSH_MSG_USERAUTH_SUCCESS messages should be passed to the 
         method. */

      auth->state = SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE;

      /* Send an authentication request to the other side. */
      ssh_cross_down_send_encode(auth->down, SSH_CROSS_PACKET,
                                 SSH_FORMAT_CHAR,
                                 (unsigned int) SSH_MSG_USERAUTH_REQUEST,
                                 SSH_FORMAT_UINT32_STR,
                                   auth->user, strlen(auth->user), 
                                 SSH_FORMAT_UINT32_STR,
                                   auth->service, strlen(auth->service), 
                                 SSH_FORMAT_UINT32_STR,
                                   auth->methods[i].name,
                                   strlen(auth->methods[i].name),
                                 SSH_FORMAT_DATA,
                                   ssh_buffer_ptr(packet),
                                   ssh_buffer_len(packet),
                                 SSH_FORMAT_END);
      auth->waiting_response_count++;
      break;

    default:
      ssh_fatal("ssh_authc_completion_proc: unknown result %d", (int)result);
    }
}

/* This is called after a method has failed, and attempts the next
   potentially productive method. 

   This may get called for NONINTERACTIVE requests performed when the
   protocol starts.  That situation can be identified by
   productive_methods being NULL.  In that case, we don't start the
   next method automatically but instead just return. */

void ssh_authc_start_next_method(SshAuthClient auth)
{
  int i;
  const char *remaining;
  char *first;

  SSH_DEBUG(6, ("next method"));

  /* There is danger that this might get called recursively if every productive
     authentication method immediately calls the completion procedure with
     FAIL.  To avoid that, we set a flag indicating that we are currently
     starting the next method, loop here until one manages to do something,
     and abort here if we would just be looping forever. */
  if (auth->starting_next_method)
    {
      auth->next_method_recursed = TRUE;
      return;
    }
  auth->starting_next_method = TRUE;
  auth->next_method_recursed = FALSE;

restart:
  assert(auth->state == SSH_AUTHC_AUTHENTICATING ||
         auth->state == SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE);

  /* If produtive_methods == NULL, we are just starting up and performing
     NONINTERACTIVE operations.  Just return in that case. */
  if (auth->productive_methods == NULL)
    {
      auth->starting_next_method = FALSE;
      return;
    }

  /* Find the name of the next method. */
  remaining = auth->productive_methods;
  for (i = 0; i < auth->productive_method_index && remaining; i++)
    remaining = ssh_name_list_step_forward(remaining);

  /* If there are no more methods left, start over.  We never get here if
     there are no methods available. */
  if (!remaining || !*remaining)
    {
      /* Sanity check: if there are no methods available at all, abort. */
      if (!auth->productive_methods || !*auth->productive_methods)
        {
          ssh_authc_both_disconnect(auth, 
                                    "No authentication methods available.");
          auth->starting_next_method = FALSE;
          return;
        }

      /* Return to the beginning. */
      auth->productive_method_index = 0;
      goto restart;
    }

  /* Get the name of the method to use. */
  first = ssh_name_list_get_name(remaining);
  if (!first)
    ssh_fatal("ssh_authc_start_next_method: first == NULL");

  /* Increment the productive method index. */
  auth->productive_method_index++;
  
  /* Find the entry corresponding to the method name. */
  for (i = 0; auth->methods[i].name; i++)
    if (strcmp(auth->methods[i].name, first) == 0)
      {
        /* Found it. */
        /* Sanity check: it should certainly not have any data saved. */
        assert(auth->state_placeholders[i] == NULL);

        /* Start the new method.  Note that it may result in a recursive
           call to this function. */
        auth->active_method_index = i;
        (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_START, auth->user,
                                 0, NULL,
                                 auth->session_id, auth->session_id_len,
                                 &auth->state_placeholders[i],
                                 ssh_authc_completion_proc, (void *)auth,
                                 auth->method_context);

        /* Free the method name. */
        ssh_xfree(first);

        /* If this flag is true, the call above resulted in a recursive
           call to this function.  Turn it into a loop. */
        if (auth->next_method_recursed)
          {
            auth->next_method_recursed = FALSE;
            goto restart;
          }

        auth->starting_next_method = FALSE;
        return;
      }

  /* We should never have methods on the list that we don't support. */
  ssh_fatal("ssh_authc_start_next_method: first '%.100s' not found!", first);
}

/* This function is called when SSH_MSG_USERAUTH_FAILURE is received from
   the network.  This takes the productive authentication methods from the
   message, intersects them with supported methods, and sets the productive
   methods array.  This generates a disconnect if there are no productive
   continuations left.

   If `cont' == TRUE, return immediately after the continuations have been 
   processed; don't start new authentication methods.

   Any waiting authentications must already have been aborted before this
   is called. */

void ssh_authc_process_failure(SshAuthClient auth, const unsigned char *data,
                               size_t len, Boolean cont)
{
  char *continuations, *productive;
  size_t bytes;
  Boolean partial_success;

  SSH_DEBUG(6, ("process_failure  cont = %d", cont));

  /* We should only be called in normal state.  If we were waiting for
     continuation packets, the method has been aborted before calling this. 

     The state may also be SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE. */

  assert(auth->state == SSH_AUTHC_AUTHENTICATING || 
         auth->state == SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE);

  /* Extract the list of productive continuations. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &continuations, NULL,
                           SSH_FORMAT_BOOLEAN, &partial_success,
                           SSH_FORMAT_END);
  if (bytes == 0)
    { /*Bad FAILURE packet. */
      ssh_authc_both_disconnect(auth, "Bad failure packet");
      return;
    }
  SSH_DEBUG(6, ("process_failure: continuations '%.100s' partial %d", 
                continuations, (int)partial_success));

  /* Any active methods should already have been aborted. */

  if (cont == FALSE)
    {
      assert(auth->active_method_index == -1);

      /* Sanity check: are we still waiting for a request? */
      if (auth->waiting_response_count == 0)
        {
          ssh_authc_both_disconnect(auth, "More failure responses than "
                                    "requests");
          ssh_xfree(continuations);
          return;
        }

      /* Decrement the count of responses still due. */
      auth->waiting_response_count--;
  
      /* Are there still more requests out there? */
      if (auth->waiting_response_count > 0)
        {
          /* Do not start new requests until on the last response. */
          ssh_xfree(continuations);
          return;
        }
    }  

  /* Compute the intersection of the productive continuations and the
     supported methods. */
  productive = ssh_name_list_intersection(auth->methods_string, continuations);
  ssh_xfree(continuations);

  /* If we have no productive continuations left, abort. */
  if (strcmp(productive, "") == 0)
    {
      ssh_authc_both_disconnect(auth, 
                         "No further authentication methods available.");
      ssh_xfree(productive);
      return;
    }
  SSH_DEBUG(6, ("process_failure: productive = %s", productive));

  /* Check if we should update the methods and start over with the first
     productive method in the new situation. */

  if (auth->productive_methods == NULL)
    {
      auth->productive_methods = productive;
      auth->productive_method_index = 0;
    }
  else
    {
      if (strcmp(productive, auth->productive_methods) == 0)
        ssh_xfree(productive);
      else
        {
          /* The methods have changed - presumably we have succeeded in some
             authentication.  Start over from the beginning of the list. */
          if (auth->productive_methods)
            ssh_xfree(auth->productive_methods);
          auth->productive_methods = productive;
          auth->productive_method_index = 0;
        }
    }

  /* Continue with the next productive authentication method. */

  if (cont == FALSE)
    ssh_authc_start_next_method(auth);
}

/* Cancel the current authentication method.  This is called if we are
   waiting for a continuation packet, but receive some other packet. */

void ssh_authc_cancel_current_method(SshAuthClient auth)
{
  int i;

  /* Sanity check: we should be waiting for a continuation. */
  assert(auth->state == SSH_AUTHC_WAITING_CONTINUATION ||
         auth->state == SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE);

  assert(auth->active_method_index != -1);

  /* Abort the active method.  Note that the abort operation should
     never call the completion procedure. */
  auth->state = SSH_AUTHC_ABORTING;
  i = auth->active_method_index;
  (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_ABORT, auth->user, 0, NULL,
                           auth->session_id, auth->session_id_len,
                           &auth->state_placeholders[i],
                           NULL, NULL, auth->method_context);

  /* Sanity check: the abort operation should have freed any saved data. */
  assert(auth->state_placeholders[i] == NULL);

  /* Make us ready to process the next authentication operation. */
  auth->state = SSH_AUTHC_AUTHENTICATING;
  auth->active_method_index = -1;
}

/* This is called whenever a SSH_MSG_USERAUTH_BANNER message is received.
   This extracts the string from the message, and sends it up as a
   DEBUG message.  The arguments contain the packet body. */

void ssh_authc_process_banner(SshAuthClient auth, 
                              const unsigned char *data, size_t len)
{
  unsigned char *msg;

  /* Decode the packet body. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR, &msg, NULL,
                       SSH_FORMAT_END) == 0)
    {
      ssh_authc_both_disconnect(auth, "Bad SSH_MSG_USERAUTH_BANNER packet");
      return;
    }

  /* Send up a DEBUG messagge with type indicating that it should be
     displayed. */
  ssh_cross_up_send_debug(auth->up, SSH_DEBUG_DISPLAY, "%s", msg);

  /* Free the message. */
  ssh_xfree(msg);
}

/* This function is called whenever a packet is received from down (that is,
   from the server or from the transport layer protocol).  This processes
   the packet, which may involve starting new authentications or
   sending up success and shortcircuiting communications. */

void ssh_authc_down_received_packet(SshCrossPacketType type,
                                    const unsigned char *data, size_t len,
                                    void *context)
{
  SshAuthClient auth = (SshAuthClient)context;
  unsigned int packet_type;
  size_t bytes;
  int i;
  SshBuffer *buffer;

  /* When we change state to DEAD, we prevent incoming packets from down.
     Thus, this should not get called when DEAD. */
  assert(auth->state != SSH_AUTHC_DEAD);

  switch (type)
    {
    case SSH_CROSS_PACKET:
      /* Received a data packet from the server. */
      SSH_DEBUG(6, ("down_received_packet: PACKET"));
      /* Decode packet type and skip the type. */
      bytes = ssh_decode_array(data, len,
                               SSH_FORMAT_CHAR, &packet_type,
                               SSH_FORMAT_END);
      if (bytes == 0)
        {
          ssh_authc_both_disconnect(auth, "Bad packet in authentication");
          return;
        }
      data += bytes;
      len -= bytes;

      /* Process the remaining of the packet according to its type. */
      switch (auth->state)
        {
        case SSH_AUTHC_WAITING_STARTUP:
          /* Should not receive data packets before STARTUP... to next case */
        case SSH_AUTHC_AUTHENTICATED:
          /* Should be shortcircuiting and not receiving packets... */
          ssh_fatal("ssh_authc_down_received_packet: packet %d in state %d",
                    (int)packet_type, (int)auth->state);

        case SSH_AUTHC_AUTHENTICATING:
          switch (packet_type)
            {
            case SSH_MSG_USERAUTH_SUCCESS:
              /* Authentication was successful. */
              ssh_authc_process_success(auth);
              break;
              
            case SSH_MSG_USERAUTH_FAILURE:
              /* Authentication failed. */
              ssh_authc_process_failure(auth, data, len, FALSE);
              break;

            case SSH_MSG_USERAUTH_BANNER:
              /* Received a banner message. */
              ssh_authc_process_banner(auth, data, len);
              break;

            default:
              /* Received something else.  Disconnect. */
              ssh_authc_both_disconnect(auth, "Unexpected response packet");
              return;
            } /* end of switch (packet_type) */
          break;

        case SSH_AUTHC_WAITING_CONTINUATION:
          switch (packet_type)
            {
            case SSH_MSG_USERAUTH_SUCCESS:
              /* There success was probably for an earlier request, though
                 theoretically it could be for the partical request as 
                 well. */
              ssh_authc_cancel_current_method(auth);
              ssh_authc_process_success(auth);
              break;

            case SSH_MSG_USERAUTH_FAILURE:
              /* The failure could be either for the request being waited
                 or some earlier request.  If there are more than one
                 requests being waited, we let the current method continue
                 and basically ignore the earlier failure (but the count of
                 requests out is decremented).  A later failure will update
                 the productive continuations anyway.  If we only have one
                 outstanding request, the server rejected our request
                 instead of sending a continuation packet, and we must
                 process the failure now. */
              if (auth->waiting_response_count > 1)
                {
                  /* Still requests out. */
                  break;
                }
              /* This is the only request out; must abort the method
                 and process the failure normally. */
              ssh_authc_cancel_current_method(auth);
              ssh_authc_process_failure(auth, data, len, FALSE);
              break;



            case SSH_MSG_USERAUTH_BANNER:
              /* Received a banner message. */
              ssh_authc_process_banner(auth, data, len);
              break;

            default:
              /* Received some other type of packet.  This is normal,
                 as we are expecting a continuation packet.  Such packets
                 are in a preallocated range.  Any valid continuation packets
                 are passed to the appropriate method.  Other packets cause
                 disconnection. */
              if (packet_type >= SSH_FIRST_USERAUTH_METHOD_PACKET &&
                  packet_type <= SSH_LAST_USERAUTH_METHOD_PACKET)
                {
                  /* Decrement the count of responses being waited. */
                  if (auth->waiting_response_count == 0)
                    {
                      ssh_authc_cancel_current_method(auth);
                      ssh_authc_both_disconnect(auth,
                                                "Too many auth responses");
                      break;
                    }
                  auth->waiting_response_count--;

                  /* It is a valid continuation packet.  Put it in a buffer
                     and pass to the authentication method. */
                  buffer = ssh_buffer_allocate();
                  ssh_buffer_append(buffer, data, len);
                  i = auth->active_method_index;
                  auth->state = SSH_AUTHC_AUTHENTICATING;
                  (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_CONTINUE,
                                           auth->user, packet_type, buffer,
                                           auth->session_id,
                                           auth->session_id_len,
                                           &auth->state_placeholders[i],
                                           ssh_authc_completion_proc,
                                           (void *)auth, auth->method_context);
                  /* Free the packet buffer. */
                  ssh_buffer_free(buffer);
                  break;
                }

              /* Received an unexpected packet type. */
              ssh_authc_cancel_current_method(auth);
              ssh_authc_both_disconnect(auth,
                                        "Bad continuation packet number");
              break;
            } /* end of switch (packet_type) */
          break;

        case SSH_AUTHC_WAITING_CONTINUATION_MULTIPLE:
          if (packet_type == SSH_MSG_USERAUTH_BANNER)
            {
              /* Received a banner message. */
              ssh_authc_process_banner(auth, data, len);
              break;
            }
          
          /* process the SSH_MSG_USERAUTH_FAILURE continuation modes */
         
          if (packet_type == SSH_MSG_USERAUTH_FAILURE)
            ssh_authc_process_failure(auth, data, len, TRUE);

          if ((packet_type >= SSH_FIRST_USERAUTH_METHOD_PACKET &&
               packet_type <= SSH_FIRST_USERAUTH_METHOD_PACKET) ||
              packet_type == SSH_MSG_USERAUTH_FAILURE ||
              packet_type == SSH_MSG_USERAUTH_SUCCESS)
            {
              /* Decrement the count of responses being waited. */
              if (auth->waiting_response_count == 0)
                {
                  ssh_authc_cancel_current_method(auth);
                  ssh_authc_both_disconnect(auth,
                                            "Too many auth responses");
                  break;
                }
              auth->waiting_response_count--;
              
              /* It is a valid continuation packet.  Put it in a buffer
                 and pass to the authentication method. */
              buffer = ssh_buffer_allocate();
              ssh_buffer_append(buffer, data, len);
              i = auth->active_method_index;
              auth->state = SSH_AUTHC_AUTHENTICATING;
              (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_CONTINUE,
                                       auth->user, packet_type, buffer,
                                       auth->session_id,
                                       auth->session_id_len,
                                       &auth->state_placeholders[i],
                                       ssh_authc_completion_proc,
                                       (void *)auth, auth->method_context);
              /* Free the packet buffer. */
              ssh_buffer_free(buffer);
              break;
            }

          /* Received an unexpected packet type. */
          ssh_authc_cancel_current_method(auth);
          ssh_authc_both_disconnect(auth,
                                    "Bad continuation packet.");
          break;

        default:
          ssh_fatal("ssh_authc_down_received_packet: unknown state %d",
                    (int)auth->state);
        } /* end of switch (auth->state) */
      break;

    case SSH_CROSS_DISCONNECT:
      /* Received a disconnect packet from down.  Pass it up; the higher level
         will presumably destroy us soon. */
      SSH_DEBUG(6, ("down_received_packet: DISCONNECT"));
      ssh_cross_up_send(auth->up, SSH_CROSS_DISCONNECT, data, len);
      ssh_cross_up_send_eof(auth->up);
      break;

    case SSH_CROSS_DEBUG:
      /* Received a debug packet from down.  Pass it up; the higher level
         will presumably display it somehow (or ignore it).  We discard
         the packet if there's too much data in the buffers. */
      SSH_DEBUG(6, ("down_received_packet: DEBUG"));
      if (ssh_cross_up_can_send(auth->up))
        ssh_cross_up_send(auth->up, SSH_CROSS_DISCONNECT, data, len);
      break;

    case SSH_CROSS_STARTUP:
      /* Received a startup packet from down.  This indicates that the
         transport layer link is now active.  Normal data packets
         can follow this packet, but cannot come before it. */
      SSH_DEBUG(6, ("down_received_packet: STARTUP"));
      assert(auth->state == SSH_AUTHC_WAITING_STARTUP);

      /* Pass the packet up. */
      ssh_cross_up_send(auth->up, SSH_CROSS_STARTUP, data, len);

      /* Extract session id from the STARTUP packet. */
      assert(auth->session_id == NULL);
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           SSH_FORMAT_UINT32_STR, 
                             &auth->session_id, &auth->session_id_len,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_authc_down_received_packet: bad STARTUP packet.");

      /* Set state to indicate we are now authenticating. */
      auth->state = SSH_AUTHC_AUTHENTICATING;

      /* Start any non-interactive authentications. */
      for (i = 0; i < auth->num_methods; i++)
        {
          /* Try a method.  No user interaction should happen since we
             request with NONINTERACTIVE.  The completion proc will recognize
             from productive_continuations == NULL that we are in this
             state, and will not automatically start the next method. */
          auth->active_method_index = i;
          (*auth->methods[i].proc)(SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE,
                                   auth->user, 0, NULL,
                                   auth->session_id, auth->session_id_len,
                                   &auth->state_placeholders[i],
                                   ssh_authc_completion_proc, (void *)auth,
                                   auth->method_context);
          /* Abort if it is expecting continuation packets. */
          if (auth->state != SSH_AUTHC_AUTHENTICATING)
            break;
        }

      /* We didn't send any requests.  Send a "none" request. */

      if (auth->state == SSH_AUTHC_AUTHENTICATING)
        {
          auth->active_method_index = -1;
          ssh_authc_completion_proc(SSH_AUTH_CLIENT_SEND, auth->user, NULL,
                                    (void *)auth);
        }
      break;

    case SSH_CROSS_ALGORITHMS:
      /* Received an altgorithms packet from down. Pass it up. */
      SSH_DEBUG(6, ("down_received_packet: ALGORITHMS"));
      ssh_cross_up_send(auth->up, SSH_CROSS_ALGORITHMS, data, len);
      break;

    default:
      /* We received some unknown packet from down.  We'll display a debugging
         message about it, and then pass it up.  This makes future updates
         less painless than aborting would. */
      SSH_TRACE(0, ("down_received_packet: unknown type %d", (int)type));
      ssh_cross_up_send(auth->up, type, data, len);
      break;
    }
}

/* This is called when we received EOF from the server.  We just pass the
   EOF up, and the presumably the higher level will eventually destroy us. */

void ssh_authc_down_received_eof(void *context)
{
  SshAuthClient auth = (SshAuthClient)context;

  /* Send EOF up. */
  ssh_cross_up_send_eof(auth->up);
}

/* Wraps the transport layer stream into an authentication stream.  This
   will automatically handle the entire authentication dialog, and will
   call the listed authentication methods as supported by the server
   to perform authentication.

   The authentication stream talks the cross layer protocol.  It will
   immediately pass up any SSH_CROSS_LAYER_STARTUP and
   SSH_CROSS_LAYER_ALGORITHMS packets, but will not communicate other
   data until authentication is complete.
   SSH_CROSS_LAYER_AUTHENTICATED (with the user name and service name)
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

SshStream ssh_auth_client_wrap(SshStream transport,
                               const char *initial_user,
                               const char *service,
                               const SshAuthClientMethod methods[],
                               void *method_context)
{
  SshAuthClient auth;
  int i;
  SshBuffer buffer;

  /* Allocate the protocol context. */
  auth = ssh_xcalloc(1, sizeof(*auth));

  /* Initialize state. */
  auth->state = SSH_AUTHC_WAITING_STARTUP;
  auth->active_method_index = -1;
  auth->starting_next_method = FALSE;
  auth->next_method_recursed = FALSE;

  /* Save initial user and service. */
  auth->user = ssh_xstrdup(initial_user);
  auth->service = ssh_xstrdup(service);

  /* Construct the string to hold the comma-separated list of supported
     authentication methods.  We use a buffer to construct the string.
     At the same time, we count the number of supported methods. */
  ssh_buffer_init(&buffer);
  for (i = 0; methods[i].name; i++)
    {
      if (i > 0)
        ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
      ssh_buffer_append(&buffer, (unsigned char *) methods[i].name,
                        strlen(methods[i].name));
    }
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  auth->methods_string = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);

  /* Save the number of methods and the pointer to the methods array. */
  auth->num_methods = i;
  auth->methods = methods;

  /* Save the method context pointer. */
  auth->method_context = method_context;

  SSH_DEBUG(6, ("%d supported methods: '%.100s'",
                auth->num_methods, auth->methods_string));

  /* Initialize placeholders for method state. */
  auth->state_placeholders = ssh_xcalloc(auth->num_methods, sizeof(void *));
  
  /* Create the upward stream and its buffers. */
  auth->up = ssh_cross_up_create(NULL,
                                 ssh_authc_up_received_eof,
                                 NULL,
                                 ssh_authc_up_destroy,
                                 (void *)auth);

  /* Create the downward cross-layer protocol stub. */
  auth->down = ssh_cross_down_create(transport,
                                     ssh_authc_down_received_packet,
                                     ssh_authc_down_received_eof,
                                     NULL,
                                     (void *)auth);

  /* Signal that we are ready to receive packets from the network (actually,
     we are waiting for the STARTUP message first, which will be sent by
     the transport layer protocol). */
  ssh_cross_down_can_receive(auth->down, TRUE);

  /* Return the upward stream. */
  return auth->up;
}

/* XXX destroy any sensitive data before shortcircuiting. */
