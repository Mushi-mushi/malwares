/*

  Author: Antti Huima <huima@ssh.fi>
          Tatu Ylonen <ylo@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jul 18 17:28:10 1996 [huima]

  The implementation of the generic event loop.

  */

/*
 * $Id: sshunixeloop.c,v 1.20 1999/05/04 02:20:24 kivinen Exp $
 * $Log: sshunixeloop.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

#ifdef HAVE_SIGNAL
#include <signal.h>
#endif /* HAVE_SIGNAL */

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */

#ifndef NSIG
#define NSIG 32
#endif

#define SSH_DEBUG_MODULE "SshEventLoop"

#define SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE 10
#define SSH_ELOOP_REQS_ARRAY_SIZE_STEP    10


static struct timeval ssh_eloop_select_timeout_no_wait = { 0L, 0L };

/* The timeouts are kept in a priority heap. The file descriptors are
   kept in an array indexed by the descriptors. Signals are indexed by
   the signal numbers. Signals are put into queue too. */

#ifdef HAVE_SIGNAL
typedef struct {
  SshSignalCallback callback;
  void *context;
} SignalRec;
#endif /* HAVE_SIGNAL */

typedef struct time_record {
  struct timeval firing_time;
  SshTimeoutCallback callback;
  void *context;
  struct time_record *next;
  Boolean killed;
} TimeRec;

typedef struct io_rec {
  int fd;
  Boolean was_nonblocking;
  SshIoCallback callback;
  void *context;
  struct io_rec *next;
  Boolean killed;
} IORec;

typedef struct {
  IORec *io_records;
  unsigned int *requests;
  int requests_array_size;
  TimeRec *time_records;
  Boolean running;
  struct timeval *select_timeout_ptr;
  Boolean in_select;
#ifdef HAVE_SIGNAL
  sigset_t used_signals;
  SignalRec *signal_records;
  Boolean fired_signals[NSIG];
  Boolean signal_fired;
#endif /* HAVE_SIGNAL */
} EventLoopRec;

static EventLoopRec ssh_eloop_event_rec;
static Boolean ssh_eloop_initialized = FALSE;
static struct timeval check_time;

static int ssh_eloop_gettimeofday(struct timeval *tp, void *ignored_tz)
{
#ifndef HAVE_GETTIMEOFDAY
  if (tp)
    {
      tp->tv_sec = ssh_time();
      tp->tv_usec = 0;
    }
#else
  gettimeofday(tp, ignored_tz);
#endif
  if (tp->tv_sec < check_time.tv_sec)
    {
      unsigned long diff;
      TimeRec *temp;

      diff = check_time.tv_sec - tp->tv_sec;
      /* Clock moved backwards, update timeouts */
      SSH_DEBUG(1, ("Time moved backwards, adjusting timeouts backwards by %d seconds",
                    diff));
      for(temp = ssh_eloop_event_rec.time_records;
          temp != NULL;
          temp = temp->next)
        {
          SSH_DEBUG(9, ("Timeout was registered at %d.",
                        temp->firing_time.tv_sec));
          temp->firing_time.tv_sec -= diff;
          SSH_DEBUG(7, ("New timeout is registered at %d.",
                        temp->firing_time.tv_sec));
        }
    }
  check_time = *tp;
  return 0;
}

/* Initializes the event loop.  This must be called before any other
   event loop, timeout, or stream function.  The IO records list
   contains no items.  The requests array contains initially
   SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE items. The array is xmallocated
   here. The signal records array contains exactly NSIG items. The
   size of the array never changes, contrary to the requests
   array. Timeouts records list contains no items, neither the list of
   fired signals. */

void ssh_event_loop_initialize(void)
{
  memset(&ssh_eloop_event_rec, 0, sizeof(ssh_eloop_event_rec));
#ifdef HAVE_SIGNAL
  sigemptyset(&ssh_eloop_event_rec.used_signals);
#endif /* HAVE_SIGNAL */
  ssh_eloop_event_rec.requests_array_size = SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE;
  ssh_eloop_event_rec.requests =
    ssh_xmalloc(sizeof(ssh_eloop_event_rec.requests[0]) *
                ssh_eloop_event_rec.requests_array_size);
#ifdef HAVE_SIGNAL
  ssh_eloop_event_rec.signal_records = ssh_xmalloc(sizeof(SignalRec) * NSIG);
#endif /* HAVE_SIGNAL */
  ssh_eloop_event_rec.running = FALSE;
  ssh_eloop_initialized = TRUE;
  
  SSH_DEBUG(4, ("Initialized the event loop."));
}

/* Abort the event loop. This causes the event loop to exit before
   the next select(). */

void ssh_event_loop_abort(void)
{
  assert(ssh_eloop_initialized);
  if (ssh_eloop_event_rec.running == TRUE)
    ssh_eloop_event_rec.running = FALSE;
}

/* Delete all timeouts. This and the subsequent, analogous functions
   are called from the event loop uninitializer. Don't call them
   from the corresponding callbacks. */

static void ssh_event_loop_delete_all_timeouts(void)
{
  TimeRec *temp;
  while (ssh_eloop_event_rec.time_records != NULL)
    {
      temp = ssh_eloop_event_rec.time_records;
      ssh_eloop_event_rec.time_records = temp->next;
      ssh_xfree(temp);
    }
}

static void ssh_event_loop_delete_all_fds(void)
{
  IORec *temp;
  while (ssh_eloop_event_rec.io_records != NULL)
    {
      temp = ssh_eloop_event_rec.io_records;
      ssh_eloop_event_rec.io_records = temp->next;
      ssh_xfree(temp);
    }
}

#ifdef HAVE_SIGNAL
static void ssh_event_loop_delete_all_signals(void)
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    {
      if (sigismember((&(ssh_eloop_event_rec.used_signals)), sig))
        ssh_unregister_signal(sig);
    }
}
#endif /* HAVE_SIGNAL */

/* Uninitialize the event loop after it has returned.
   Delete all timeouts etc. left and free the structures. */   

void ssh_event_loop_uninitialize(void)
{
  assert(ssh_eloop_initialized);
  ssh_event_loop_delete_all_timeouts();
  ssh_event_loop_delete_all_fds();

#ifdef HAVE_SIGNAL
  ssh_event_loop_delete_all_signals();
#endif /* HAVE_SIGNAL */

  ssh_xfree(ssh_eloop_event_rec.requests);

#ifdef HAVE_SIGNAL
  ssh_xfree(ssh_eloop_event_rec.signal_records);
#endif /* HAVE_SIGNAL */

  SSH_DEBUG(4, ("Uninitialized the event loop."));
}

/* The signal handler. Insert a new fired signal structure to the
   list of fired signals. Block signals until the insertion has
   finished so that other catched signals don't mess the list up. */

#ifdef HAVE_SIGNAL
static RETSIGTYPE ssh_event_loop_signal_handler(int sig)
{
  sigset_t old_set;

  SSH_DEBUG(7, ("Got signal number: %d", sig));
  assert(sig > 0 && sig <= NSIG);

  /* Signals are blocked during the execution of this call. */
  sigprocmask(SIG_BLOCK, &ssh_eloop_event_rec.used_signals, &old_set);
  
  if (ssh_eloop_event_rec.in_select)
    {
      /* We were in select(), deliver the callback immediately. */
      if (ssh_eloop_event_rec.signal_records[sig - 1].callback)
        (*ssh_eloop_event_rec.signal_records[sig - 1].callback)(sig,
           ssh_eloop_event_rec.signal_records[sig - 1].context);
    }
  else
    {
      /* We are currently processing a callback; deliver the signal callback
         when the current callback returns. */
      ssh_eloop_event_rec.signal_fired = TRUE;
      ssh_eloop_event_rec.fired_signals[sig - 1] = TRUE;
    }

  sigprocmask(SIG_SETMASK, &old_set, NULL);

  /* Cancel the select timeout because the signal might have arrived
     after the signals have been handled before the select(). */
  ssh_eloop_event_rec.select_timeout_ptr = &ssh_eloop_select_timeout_no_wait;
}
#endif /* HAVE_SIGNAL */

/* Compare two struct timevals. */
static int ssh_event_loop_compare_time(struct timeval *first,
                                       struct timeval *second)
{
  return
    (first->tv_sec  < second->tv_sec)  ? -1 :
    (first->tv_sec  > second->tv_sec)  ?  1 :
    (first->tv_usec < second->tv_usec) ? -1 :
    (first->tv_usec > second->tv_usec) ?  1 : 0;
}

/* Convert relative timeout to absolute. */
static void ssh_eloop_convert_relative_to_absolute(long seconds,
                                                   long microseconds,
                                                   struct timeval *timeval)
{
  assert(microseconds >= 0 && microseconds < 1000000L);
  ssh_eloop_gettimeofday(timeval, NULL);
  timeval->tv_sec += seconds;
  timeval->tv_usec += microseconds;
  if (timeval->tv_usec > 999999L)
    {
      timeval->tv_usec -= 1000000L;
      timeval->tv_sec++;
    }
}

/* Register a timeout. Search for the correct place and insert 
   the timeout. */

void ssh_register_timeout(long seconds,
                          long microseconds,
                          SshTimeoutCallback callback,
                          void *context)
{
  TimeRec **iter;
  TimeRec *created = ssh_xmalloc(sizeof(*created));

  assert(seconds >= 0 && seconds < 40000000L);
  assert(microseconds >= 0);
  assert(ssh_eloop_initialized);

  /* Move full seconds from microseconds to seconds. */
  seconds += microseconds / 1000000L;
  microseconds %= 1000000L;

  /* Convert to absolute time and initialize timeout record. */
  ssh_eloop_convert_relative_to_absolute(seconds, microseconds,
                                         &created->firing_time);
  created->callback = callback;
  created->context = context;
  created->killed = FALSE;

  /* Insert the new timeout in the sorted list of timeouts. */
  iter = &ssh_eloop_event_rec.time_records;
  while ((*iter != NULL) &&
         (ssh_event_loop_compare_time(&((*iter)->firing_time),
                                      &(created->firing_time)) < 0))
    iter = &((*iter)->next);

  created->next = *iter;
  *iter = created;

  SSH_DEBUG(7, ("Timeout registered at %d.", created->firing_time.tv_sec));
}

/* Registers an idle timeout to be called when the system has been idle
   for the specified amount of time. */

void ssh_register_idle_timeout(long seconds,
                               long microseconds,
                               SshTimeoutCallback callback,
                               void *context)
{
  SSH_TRACE(1, ("Idle timeouts not yet implemented."));
  /* XXX Note: it is a legal implementation to never call idle timeouts.
     Implement this later. */
}

/* Cancel all timeouts that call `callback' with context `context'.
   SSH_ALL_CALLBACKS and SSH_ALL_CONTEXTS can be used as wildcards. */

void ssh_cancel_timeouts(SshTimeoutCallback callback, void *context)
{
  TimeRec *iter = ssh_eloop_event_rec.time_records;

  assert(ssh_eloop_initialized);

  while (iter != NULL)
    {
      if ((iter->context == context ||
           context == SSH_ALL_CONTEXTS) &&
          (iter->callback == callback ||
           callback == SSH_ALL_CALLBACKS) &&
          iter->killed == FALSE)
        {
          SSH_DEBUG(7, ("Removed timeout at %d.", iter->firing_time.tv_sec));
          iter->killed = TRUE;
        }
      iter = iter->next;
    }
}

/* Register a new signal. Add the signal action with the sigaction()
   system call. Also insert the callback and context information to
   the static array of signal callbacks, indexed by the signal
   number. */

#ifdef HAVE_SIGNAL
void ssh_register_signal(int sig, SshSignalCallback callback,
                         void *context)
{
  struct sigaction action;
  sigset_t mask, old_mask;

  assert(ssh_eloop_initialized);
  
  if (sig <= 0 || sig > NSIG)
    {
      SSH_DEBUG(7, ("Registering bad signal %d ignored.", sig));
      return;
    }

  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  sigprocmask(SIG_BLOCK, &mask, &old_mask);

  sigaddset(&(ssh_eloop_event_rec.used_signals), sig);
  ssh_eloop_event_rec.signal_records[sig - 1].callback = callback;
  ssh_eloop_event_rec.signal_records[sig - 1].context = context;
  action.sa_handler = ssh_event_loop_signal_handler;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  sigaction(sig, &action, NULL);

  sigprocmask(SIG_SETMASK, &old_mask, (sigset_t *) NULL);
  
  SSH_DEBUG(7, ("Registered signal %d.", sig));
}
#endif /* HAVE_SIGNAL */

/* Unregister a signal. Set the signal action to its system default
   with the sigaction() system call. Also set the callback and context
   information of the signal to NULLs. */

#ifdef HAVE_SIGNAL
void ssh_unregister_signal(int sig)
{
  struct sigaction action;
  sigset_t mask, old_mask;
  Boolean previously_fired;

  assert(ssh_eloop_initialized);
  
  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  sigprocmask(SIG_BLOCK, &mask, &old_mask);
  
  action.sa_handler = SIG_DFL;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  sigaction(sig, &action, NULL);
  sigdelset(&ssh_eloop_event_rec.used_signals, sig);

  /* Save the signal status. */
  previously_fired = ssh_eloop_event_rec.fired_signals[sig - 1];
  ssh_eloop_event_rec.fired_signals[sig - 1] = FALSE;

  ssh_eloop_event_rec.signal_records[sig - 1].callback = NULL;
  ssh_eloop_event_rec.signal_records[sig - 1].context = NULL;

  sigprocmask(SIG_SETMASK, &old_mask, (sigset_t *) NULL);

  if (previously_fired)
    {
      SSH_DEBUG(1, ("Reissuing signal for which callback was not yet delivered."));
      kill(getpid(), sig);
    }
  
  SSH_DEBUG(7, ("Unregistered signal %d.", sig));
}
#endif /* HAVE_SIGNAL */

/* Register a file descriptor. Create a structure and add it to the
   beginning of the list of IO records. Also set the `fd'th entry in
   the requests array to SSH_IO_READ, expanding the array in size
   if necessary. */

void ssh_io_register_fd(int fd, SshIoCallback callback, void *context)
{
  IORec *created = ssh_xmalloc(sizeof(*created));
  IORec **iter;

  assert(ssh_eloop_initialized);
  
  created->callback = callback;
  created->context = context;
  created->fd = fd;
  created->killed = FALSE;
  created->was_nonblocking =
    (fcntl(fd, F_GETFL, 0) & (O_NONBLOCK|O_NDELAY)) != 0;

  /* Make the file descriptor use non-blocking I/O. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

  if (fd >= ssh_eloop_event_rec.requests_array_size)
    {
      assert(fd < 10000);  /* Sanity check... */
      ssh_eloop_event_rec.requests_array_size +=
        SSH_ELOOP_REQS_ARRAY_SIZE_STEP;
      if (fd >= ssh_eloop_event_rec.requests_array_size)
        ssh_eloop_event_rec.requests_array_size = fd + 1;
      ssh_eloop_event_rec.requests =
        ssh_xrealloc(ssh_eloop_event_rec.requests,
                     ssh_eloop_event_rec.requests_array_size *
                     sizeof(ssh_eloop_event_rec.requests[0]));
    }
  ssh_eloop_event_rec.requests[fd] = 0;

  /* Add the newly created structure to the END of the list. */
  iter = &ssh_eloop_event_rec.io_records;
  while ((*iter) != NULL)
    iter = &((*iter)->next);
  *iter = created;
  created->next = NULL;

  SSH_DEBUG(7, ("Registered file descriptor %d.", fd));
}

/* Unregister a file descriptor. */

void ssh_io_unregister_fd(int fd, Boolean keep_nonblocking)
{
  IORec *iter;

  assert(ssh_eloop_initialized);
  iter = ssh_eloop_event_rec.io_records;
  while (iter != NULL)
    {
      if ((iter->fd == fd) && (iter->killed == FALSE))
        {
          if (!iter->was_nonblocking && !keep_nonblocking)
            {
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
              fcntl(iter->fd, F_SETFL, 
                    fcntl(iter->fd, F_GETFL, 0) & ~O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
              fcntl(iter->fd, F_SETFL,
                    fcntl(iter->fd, F_GETFL, 0) & ~O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
            }
          iter->killed = TRUE;
          SSH_DEBUG(7, ("Killed the file descriptor %d, waiting for removal",
                        fd));
          return;
        }
      iter = iter->next;
    }
  /* File descriptor was not found. */
  ssh_warning("ssh_io_unregister_fd: file descriptor %d was not found.", fd);
}

/* Set the IO request(s) for a file descriptor. The file descriptor
   must have been registered previously to the event loop; otherwise
   the requests table might have less items than `fd'.
   ssh_fatal() is called if this happens. */

void ssh_io_set_fd_request(int fd, unsigned int request)
{
  if (fd >= ssh_eloop_event_rec.requests_array_size)
    ssh_fatal("File descriptor %d exceeded the array size in "
          "ssh_io_set_fd_request.", fd);
  ssh_eloop_event_rec.requests[fd] = request;
}

/* Run the event loop. */

void ssh_event_loop_run(void)
{
  struct timeval current_time, modified_time, idle_time, prev_time;
  struct timeval select_timeout;
  TimeRec *time_temp;
  IORec *iorec_temp;
  IORec **iorec_ptr;
  int select_return_value;
  int max_fd;
  int num_files_selected;
  Boolean done_something;
  fd_set readfds, writefds;

#ifdef HAVE_SIGNAL
  sigset_t old_set;
#endif /* HAVE_SIGNAL */

  SSH_DEBUG(4, ("Starting the event loop."));
  assert(ssh_eloop_initialized);
  
  ssh_eloop_event_rec.running = TRUE;
  ssh_eloop_event_rec.in_select = FALSE;

  done_something = FALSE;
  ssh_eloop_gettimeofday(&prev_time, NULL);
  while (1)
    {

#ifdef HAVE_SIGNAL
      /* Handle signals. */
      while (ssh_eloop_event_rec.signal_fired)
        {
          int i;

          /* We don't want to get signals during this because we're
             modifying the signals list. */
          sigprocmask(SIG_BLOCK, &ssh_eloop_event_rec.used_signals, &old_set);
          for (i = 1; i <= NSIG; i++)
            {
              if (ssh_eloop_event_rec.fired_signals[i - 1])
                {
                  ssh_eloop_event_rec.fired_signals[i - 1] = FALSE;
                  SSH_DEBUG(7, ("Calling a signal handler."));
                  if (ssh_eloop_event_rec.signal_records[i - 1].callback)
                    (*ssh_eloop_event_rec.signal_records[i - 1].callback)(i,
                        ssh_eloop_event_rec.signal_records[i - 1].context);
                  done_something = TRUE;
                }
            }
          ssh_eloop_event_rec.signal_fired = FALSE;
          
          /* Turn the mask off so that signals that have arrived during
             the iteration get into the queue. Then start the iteration
             again if the queue is not empty. */
          sigprocmask(SIG_SETMASK, &old_set, NULL);
        }
#endif /* HAVE_SIGNAL */

      ssh_eloop_event_rec.select_timeout_ptr = NULL;

      /* Get current time */
      ssh_eloop_gettimeofday(&current_time, NULL);
      
      /* If there are any timeouts to be fired fire them now.
         If there are any timeouts waiting set the timeout of the 
         select() call to match the earliest of the timeouts. */
      if (ssh_eloop_event_rec.time_records != NULL)
        {
          /* Calculate idle time from last time when something else than idle
             timeouts was done */
          if (done_something)
            {
              idle_time.tv_sec = 0;
              idle_time.tv_usec = 0;
            }
          else
            {
              idle_time.tv_sec = current_time.tv_sec - prev_time.tv_sec;
              idle_time.tv_usec = current_time.tv_usec - prev_time.tv_usec;
              if (idle_time.tv_usec < 0)
                {
                  idle_time.tv_sec--;
                  idle_time.tv_usec += 1000000L;
                }
            }
          
          while ((time_temp = ssh_eloop_event_rec.time_records) != NULL)
            {
              if (time_temp->killed == FALSE)
                {
                  modified_time = current_time;
                  if (modified_time.tv_usec >= 1000000)
                    {
                      modified_time.tv_usec -= 1000000;
                      modified_time.tv_sec++;
                    }
                  if (ssh_event_loop_compare_time(&(time_temp->firing_time),
                                                  &modified_time) > 0)
                    break;

                  ssh_eloop_event_rec.time_records =
                    ssh_eloop_event_rec.time_records->next;
                  
                  /* It is safe to add or kill timeouts in the
                     callback. */
                  SSH_DEBUG(7, ("Calling a timeout callback."));
                  (*time_temp->callback)(time_temp->context);
                  done_something = TRUE;
#if 0
                  /* Removed this to make event loop fair. After this
                     modification the select part below also gets some time
                     //kivinen */ 
                  ssh_eloop_gettimeofday(&current_time, NULL);
#endif
                }
              else
                {
                  ssh_eloop_event_rec.time_records =
                    ssh_eloop_event_rec.time_records->next;
                }
              ssh_xfree(time_temp);
            }
          /* If there are any time records in the queue the first of
             them is not killed. */
          /* Determine the amount of time until the next timeout.  This can be
             in the past, because we run expire queue only once. */
          ssh_eloop_gettimeofday(&current_time, NULL);
          if (ssh_eloop_event_rec.time_records != NULL)
            {
              unsigned long sec, usec;

              sec = ssh_eloop_event_rec.time_records->firing_time.tv_sec;
              usec = ssh_eloop_event_rec.time_records->firing_time.tv_usec;

              if (sec < current_time.tv_sec ||
                  (sec == current_time.tv_sec &&
                   usec < current_time.tv_usec))
                {
                  sec = 0;
                  usec = 0;
                }
              else
                {
                  sec = sec - current_time.tv_sec;
                  if (usec < current_time.tv_usec)
                    {
                      sec--;
                      usec = usec + 1000000 - current_time.tv_usec;
                    }
                  else
                    usec = usec - current_time.tv_usec;
                }
              
              select_timeout.tv_sec = sec;
              select_timeout.tv_usec = usec;
                  
              ssh_eloop_event_rec.select_timeout_ptr = &select_timeout;
              SSH_DEBUG(8, ("Select timeout: %ld seconds, %ld usec.",
                            ssh_eloop_event_rec.select_timeout_ptr->tv_sec,
                            ssh_eloop_event_rec.select_timeout_ptr->tv_usec));
            }
        }

      /* Choose the file descriptors to be selected. */
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      num_files_selected = 0;
      max_fd = -1;

      iorec_temp = ssh_eloop_event_rec.io_records;
      while (iorec_temp != NULL)
        {
          if (iorec_temp->killed == FALSE)
            {
              if (ssh_eloop_event_rec.requests[iorec_temp->fd] & SSH_IO_READ)
                {
                  num_files_selected++;
                  FD_SET(iorec_temp->fd, &readfds);
                }
              if (ssh_eloop_event_rec.requests[iorec_temp->fd] & SSH_IO_WRITE)
                {
                  FD_SET(iorec_temp->fd, &writefds);
                  num_files_selected++;
                }
              if (max_fd < iorec_temp->fd)
                max_fd = iorec_temp->fd;
            }
          iorec_temp = iorec_temp->next;
        }
      
      /* If the select() would definitely block infinitely, return now. */
      if ((num_files_selected < 1) &&
          (ssh_eloop_event_rec.select_timeout_ptr == NULL))
        break;

      /* Exit now if the event loop has been aborted. */
      if (!ssh_eloop_event_rec.running)
        break;

      /* If we had done something (other than running idle timeouts) copy the
         current time to prev time */
      if (done_something)
        {
          prev_time = current_time;
        }

      /* Raise the in_select flag. If signals arrive during the
         select() function call, the signal handler notices that and
         calls the callback for the signal immediately. */
      ssh_eloop_event_rec.in_select = TRUE;

      if (ssh_eloop_event_rec.select_timeout_ptr != NULL &&
          ssh_eloop_event_rec.select_timeout_ptr->tv_sec == 0 &&
          ssh_eloop_event_rec.select_timeout_ptr->tv_usec != 0)
        SSH_DEBUG(8, ("select timeout: %ld %ld",
                      (long)ssh_eloop_event_rec.select_timeout_ptr->tv_sec,
                      (long)ssh_eloop_event_rec.select_timeout_ptr->tv_usec));
      
      SSH_DEBUG(8, ("Select."));
      select_return_value = select(max_fd + 1, &readfds, &writefds, NULL,
                                   ssh_eloop_event_rec.select_timeout_ptr);

      ssh_eloop_event_rec.in_select = FALSE;
      done_something = FALSE;

      switch (select_return_value)
        {
        case 0: /* Timeout */
          break;
        case -1: /* Error */
          switch (errno)
            {
            case EBADF: /* Bad file descriptor. */
              ssh_fatal("Bad file descriptor in the event loop.");
              break;
            case EINTR: /* Caught a signal. */
              SSH_DEBUG(7, ("Select exited because of a caught signal."));
              break;
            case EINVAL: /* Invalid time limit. */
              ssh_fatal("Bad time limit in the event loop.");
              break;
            }
          break;
        default: /* Some IO is ready */   
          done_something = TRUE;
          iorec_temp = ssh_eloop_event_rec.io_records;
          iorec_ptr = &(ssh_eloop_event_rec.io_records);
          while (iorec_temp != NULL)
            {
              if ((FD_ISSET(iorec_temp->fd, &readfds)) &&
                  (iorec_temp->killed == FALSE) &&
                  (ssh_eloop_event_rec.requests[iorec_temp->fd] & SSH_IO_READ))
                (*iorec_temp->callback)(SSH_IO_READ, iorec_temp->context);

              if ((FD_ISSET(iorec_temp->fd, &writefds)) &&
                  (iorec_temp->killed == FALSE) &&
                  (ssh_eloop_event_rec.requests[iorec_temp->fd] &
                   SSH_IO_WRITE))
                (*iorec_temp->callback)(SSH_IO_WRITE, iorec_temp->context);

              /* If the IO item is killed remove it now. */
              if (iorec_temp->killed == TRUE)
                {
                  SSH_DEBUG(7, ("Removed a killed IO callback."));
                  /* First set the pointer to point to the next item
                     in the list. */
                  *iorec_ptr = iorec_temp->next;

                  /* Then free the killed structure. */
                  ssh_xfree(iorec_temp);

                  /* Finally set the iteration pointer to the next item
                     in the list. */
                  iorec_temp = *iorec_ptr;
                }
              else
                {
                  iorec_ptr = &(iorec_temp->next);
                  iorec_temp = iorec_temp->next;
                }
            }
        }
    }
}
