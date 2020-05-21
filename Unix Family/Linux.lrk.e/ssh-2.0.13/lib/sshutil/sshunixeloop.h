/*

sshunixeloop.h

Author: Tatu Ylonen <ylo@ssh.fi>
	Antti Huima <huima@ssh.fi>
	Tero Kivinen <kivinen@ssh.fi>

Copyright (c) 1996-1998 SSH Communications Security, Finland
All rights reserved

Unix-specific event loop interface.  These functions are not available on all
systems.

*/

#ifndef SSHUNIXELOOP_H
#define SSHUNIXELOOP_H

/* Initializes the event loop.  This must be called before any other event
   loop, timeout, or stream function. */
void ssh_event_loop_initialize(void);

/* This function runs the event loop.  This should normally be called from
   the application main loop after the application has been initialized.
   This returns when all event loop activity has ceased (ssh_event_loop_status
   returns SSH_EVENT_LOOP_INACTIVE), or when ssh_event_loop_abort has been
   called. */
void ssh_event_loop_run(void);

/* Uninitializes the event loop, and frees resources used by it.  This
   automatically cancels any pending timeouts and unregisters file
   descriptors.  This must not be called from within an event loop
   callback. */
void ssh_event_loop_uninitialize(void);

/* When called within a call to ssh_event_loop_run, causes the event loop
   to stop running and no longer deliver callbacks.  The event loop stops
   when control returns to the bottom of the event loop. */
void ssh_event_loop_abort(void);

/* Event loop status values. */
typedef enum {
  /* The event loop is active, and has callbacks pending. */
  SSH_EVENT_LOOP_ACTIVE,

  /* There are streams for which I/O is being waited.
     The event loop will wake up when I/O is again possible. */
  SSH_EVENT_LOOP_WAITING_IO,

  /* There are no streams for which I/O is being waited, but there
     are registered timeouts. */
  SSH_EVENT_LOOP_WAITING_TIMEOUT,

  /* There are no streams for which I/O is being waited, no normal timeouts,
     but there are idle timeouts. */
  SSH_EVENT_LOOP_WAITING_IDLE_TIMEOUT,

  /* The event loop is inactive, and will never wake up unless new
     timeouts or streams are registered. */
  SSH_EVENT_LOOP_INACTIVE
} SshEventLoopStatus;

/* Returns the status of the event loop.  The possible return values were
   defined above. */
SshEventLoopStatus ssh_event_loop_status(void);

/***********************************************************************
 * Signal processing functions
 ***********************************************************************/

#ifdef HAVE_SIGNAL

/* This type represents a signal callback.  Such a function can be
   registered to be called whenever a particular signal is delivered.
   The callback function will always be called from the bottom of the
   event loop.  There are no restrictions on what can be done in the
   callback. */

typedef void (*SshSignalCallback)(int signal, void *context);

/* Registers the specified callback function to be called from the bottom
   of the event loop whenever the given signal is received.  The registration
   will remain in effect until explicitly unregistered.  If the same signal
   is received multiple times before the callback is called, the callback
   may get called only once for those multiple signals.  The `callback'
   argument may be NULL, in which case the signal will be ignored. */

void ssh_register_signal(int signal, SshSignalCallback callback,
			 void *context);

/* Restores the handling of the signal to the default behavior.  Any
   callback registered for the signal will no longer be called (even
   if the signal has already been triggered, but the callback has not
   yet been called, it is guaranteed that the callback will not get
   called for the signal if this has been called before it is
   delivered).  Note that this function restores the signal to default
   behavior (e.g., core dump), whereas setting the callback to NULL
   causes the signal to be ignored. */

void ssh_unregister_signal(int signal);

#endif /* HAVE_SIGNAL */

/***********************************************************************
 * I/O notification functions
 ***********************************************************************/

/* Notification flags for ssh_io_set_fd_request. */
#define SSH_IO_READ       1  /* request notification for data available */
#define SSH_IO_WRITE	  2  /* request notification when can output */

/* Callback functions of this type are used to receive notifications
   of I/O being possible on the file descriptor for which the callback
   is being registered.  Events is bitwise-or of the SSH_IO_ values
   defined above.  There are no restrictions on what can be done in the
   callback. */
typedef void (*SshIoCallback)(unsigned int events, void *context);

/* Registers the given file descriptor for the event loop.  This sets the
   descriptor in non-blocking mode, and registers the callback for the
   file descriptor.  Initially, no events will be requested, and
   ssh_io_set_fd_request must be called before any events will be delivered. */
void ssh_io_register_fd(int fd, SshIoCallback callback, void *context);

/* Cancels any callbacks registered for the file descriptor.  The blocking mode
   of the file descriptor will be restored to its original value.  It is
   guaranteed that no more callbacks will be received for the file descriptor
   after this fucntion has been called.  If `keep_nonblocking' is TRUE,
   the file descriptor will be left non-blocking (this may be useful
   after a fork). */
void ssh_io_unregister_fd(int fd, Boolean keep_nonblocking);

/* Specifies the types of events for which callbacks are to be delivered for
   the file descriptor.  The `events' argument is a bitwise-or of the
   SSH_IO_ values defined above.  If SSH_IO_READ is included, the callback
   will be called whenever data is available for reading.  If SSH_IO_WRITE
   is specified, the callback will be called whenever more data can be
   written to the file descriptor.  Callbacks will continue to be delivered
   from the event loop until the event is either removed from the request
   or the condition causing the event to trigger ceases to exist (e.g., via
   reading all buffered data from a socket). */
void ssh_io_set_fd_request(int fd, unsigned int events);

#endif /* SSHUNIXELOOP_H */
