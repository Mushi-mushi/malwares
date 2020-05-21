/*

sshchx11.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Public interface for SSH2 X11 forwarding channels.

*/

#ifndef SSHCHX11_H
#define SSHCHX11_H

/* This function is called whenever an open request is received for an
   X11 channel. */
void ssh_channel_x11_open(const char *type,
                          int channel_id,
                          const unsigned char *data,
                          size_t len,
                          SshConnOpenCompletionProc completion,
                          void *completion_context,
                          void *context);

/* This function is called once when a SshCommon object is created. */
void *ssh_channel_x11_create(SshCommon common);

/* This function is called once when an SshCommon object is being
   destroyed.  This should destroy all X11 channels and listeners and
   free the context. */
void ssh_channel_x11_destroy(void *context);

/* This function is called from within the context of a session channel
   in the client to request X11 forwarding for the session. */
void ssh_channel_x11_send_request(SshCommon common,
                                  int session_channel_id);

/* This function is called once for each session channel that is created.
   This should initialize per-session state for X11 forwarding.  The
   argument points to a void pointer that will be given as argument to
   the following functions.  It can be used to store the per-session
   state. */
void ssh_channel_x11_session_create(SshCommon common,
                                    void **session_placeholder);
                                        
/* This function is called once whenever a session channel is destroyed.
   This should free any X11 forwarding state related to the session; however,
   this should typically not close forwarded X11 channels. */
void ssh_channel_x11_session_destroy(void *session_placeholder);

/* This function is called in a server when an X11 forwarding request is
   received from the client. */
Boolean ssh_channel_x11_process_request(void *session_placeholder,
                                        const unsigned char *data,
                                        size_t len);

/* Returns the value of DISPLAY in the server. */
const char *ssh_channel_x11_get_display(void *session_placeholder);

/* Returns the value of the authentication protocol in the server. */
const char *ssh_channel_x11_get_auth_protocol(void *session_placeholder);

/* Returns the value of the authentication cookie in the server. */
const char *ssh_channel_x11_get_auth_cookie(void *session_placeholder);

#endif /* SSHCHX11_H */
