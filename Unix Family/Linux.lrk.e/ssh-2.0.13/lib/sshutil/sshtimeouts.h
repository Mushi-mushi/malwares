/*

sshtimeouts.h

Author: Tatu Ylonen <ylo@ssh.fi>
	Antti Huima <huima@ssh.fi>
	Tero Kivinen <kivinen@ssh.fi>

Copyright (c) 1995-1998 SSH Communications Security, Finland
              All rights reserved.

Timeout processing.  This header is part of the event loop interface.
This header is machine-independent; however, the implementation is
machine-dependent.

*/

#ifndef SSHTIMEOUTS_H
#define SSHTIMEOUTS_H

/* Special wild-card context arguments to ssh_cancel_timeouts. */
#define SSH_ALL_CALLBACKS ((SshTimeoutCallback)1)
#define SSH_ALL_CONTEXTS  ((void *)1)

/* Callback functions of this type are called when a timeout occurs.
   The function receives as argument the context supplied when the
   timeout was registered.  A timeout is delivered only once, but can
   be reregistered in the callback function.  There are no
   restrictions as to what operations can be performed in timeout
   callbacks. */
typedef void (*SshTimeoutCallback)(void *context);

/* Registers a timeout function that is to be called once when the specified
   time has elapsed.  The time may be zero, in which case the callback will
   be called as soon as possible from the bottom of the event loop.  There
   is no guarantee about the order in which callbacks with zero timeouts are
   delivered.

   The timeout will be delivered approximately after the specified time.  The
   exact time may differ somewhat from the specified time.  The timeout will
   be delivered from the bottom of the event loop (i.e., it will be delayed if
   another callback from the event loop is being executed).

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback	    the callback function to call
     context        context argument to pass to callback function. */
DLLEXPORT void DLLCALLCONV
ssh_register_timeout(long seconds, long microseconds,
		     SshTimeoutCallback callback, void *context);

/* Registers an idle timeout function.  An idle timeout will be called once
   when the system has been sufficiently idle for the specified amount of
   time.  The definition of idle is somewhat implementation-dependent, but
   typically means when it is a good time to perform cpu-intensive operations.
   There is no guarantee that the idle timeout ever gets called.  Idle timeouts
   are always delivered from the bottom of the event loop.

   The arguments are as follows:
     seconds        number of seconds the system must be idle before delivering
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback	    the callback function to call
     context        context argument to pass to callback function. */
DLLEXPORT void DLLCALLCONV
ssh_register_idle_timeout(long seconds, long microseconds,
			  SshTimeoutCallback callback, void *context);

/* Cancels any timeouts with a matching callback function and context.
   `callback' may be SSH_ALL_CALLBACKS, which matches any function, and
   `context' may be SSH_ALL_CONTEXTS, which matches any context.
   It is guaranteed that the timeout will not be delivered once it has
   been cancelled, even if it had elapsed (but not yet delivered) before
   cancelling it. */
DLLEXPORT void DLLCALLCONV
ssh_cancel_timeouts(SshTimeoutCallback callback, void *context);

#endif /* SSHTIMEOUTS_H */
