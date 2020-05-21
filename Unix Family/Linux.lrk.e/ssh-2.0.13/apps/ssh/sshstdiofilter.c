/*

  sshstdiofilter.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#include "ssh2includes.h"
#include "sshfilterstream.h"
#include "sshtcp.h"
#include "sshcommon.h"
#include "sshstdiofilter.h"
#include "sshtty.h"

#define SSH_DEBUG_MODULE "SshStdIOFilter"

#define STATE_BASIC     0
#define STATE_HAVE_CR   1
#define STATE_HAVE_ESC  2

static int stdio_filter_state = STATE_BASIC;

void ssh_cancel_nonblocking(void);
void ssh_set_nonblocking(void);

#if 1
void ssh_buffer_consume_middle(SshBuffer *buffer, size_t offset, size_t bytes);

void ssh_buffer_consume_middle(SshBuffer *buffer, size_t offset, size_t bytes)
{
    if (bytes + offset > buffer->end - buffer->offset)
        ssh_fatal("buffer_consume_middle trying to get too many bytes");

    memmove(buffer->buf + buffer->offset + offset,
            buffer->buf + buffer->offset + offset + bytes,
            buffer->end - buffer->offset - offset - bytes);
    buffer->end -= bytes;
}
#endif

void ssh_escape_char_help(int esc_char)
{
  clearerr(stderr);        /* XXX */
  ssh_leave_raw_mode(-1);
  fprintf(stderr, "\n");
  fprintf(stderr,
    "  Supported escape sequences:\n");
  fprintf(stderr,
    "  %c.  - terminate connection\n",
          esc_char);
  fprintf(stderr,
    "  %c^Z - suspend ssh\n",
          esc_char);
  fprintf(stderr,
    "  %c#  - list forwarded connections\n",
          esc_char);
  fprintf(stderr,
    "  %c?  - this message\n",
          esc_char);
  fprintf(stderr,
    "  %c-  - disable escape character uncancellably\n",
          esc_char);
  fprintf(stderr,
    "  %c&  - background ssh (when waiting for connections to terminate)\n",
          esc_char);
  fprintf(stderr,
    "  %c?  - this message\n",
          esc_char);
  fprintf(stderr,
    "  %c%c  - send the escape character by typing it twice\n",
          esc_char, esc_char);
  fprintf(stderr,
    "  (Note that escapes are only recognized immediately after newline.)\n");
  ssh_enter_raw_mode(-1);
}

void ssh_cancel_nonblocking()
{
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(0, F_SETFL, 0);
  (void)fcntl(1, F_SETFL, 0);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(0, F_SETFL, 0);
  (void)fcntl(1, F_SETFL, 0);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
}

void ssh_set_nonblocking()
{
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
  (void)fcntl(0, F_SETFL, O_NONBLOCK);
  (void)fcntl(1, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
  (void)fcntl(0, F_SETFL, O_NDELAY);
  (void)fcntl(1, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
}

void ssh_escape_char_quit(int esc_char)
{
  /* Exit non-blocking raw mode. */
  ssh_leave_raw_mode(-1);
  ssh_cancel_nonblocking();

  /* Display the escape sequence. */
  fprintf(stderr, "%c.\n", esc_char);

  /* Forcibly exit the application immediately. */
  exit(0);
}

void ssh_escape_char_background(int esc_char)
{
  clearerr(stderr);        /* XXX */
  ssh_leave_raw_mode(-1);
  ssh_cancel_nonblocking();
  fprintf(stderr, "\nBackgrounding not yet supported.\n");
  ssh_set_nonblocking();
  ssh_enter_raw_mode(-1);
}

void ssh_escape_char_suspend(int esc_char)
{
#ifdef SIGWINCH
  struct winsize oldws, newws;
#endif /* SIGWINCH */

  /* Clear errors on stdout. */
  clearerr(stderr);        /* XXX */

  /* Exit non-blocking raw mode. */
  ssh_leave_raw_mode(-1);
  ssh_cancel_nonblocking();

  /* Print the escape sequence. */
  fprintf(stderr, "%c^Z\n", esc_char);

#ifdef SIGWINCH
  /* Save old window size. */
  ioctl(fileno(stdin), TIOCGWINSZ, &oldws);
#endif /* SIGWINCH */

  /* Send the suspend signal to the program
     itself. */
  kill(getpid(), SIGTSTP);

  /* Restore non-blocking raw mode. */
  ssh_set_nonblocking();
  ssh_enter_raw_mode(-1);

#ifdef SIGWINCH
  /* Check if the window size has changed. */
  if (ioctl(fileno(stdin), TIOCGWINSZ, &newws) >= 0 &&
      (oldws.ws_row != newws.ws_row || oldws.ws_col != newws.ws_col ||
       oldws.ws_xpixel != newws.ws_xpixel || 
       oldws.ws_ypixel != newws.ws_ypixel))
    kill(getpid(), SIGWINCH);
#endif /* SIGWINCH */
}

void ssh_escape_char_list_connections(int esc_char)
{
  clearerr(stderr);        /* XXX */
  ssh_leave_raw_mode(-1);
  ssh_cancel_nonblocking();
  fprintf(stderr, "\nConnection listing not yet supported.\n");
  ssh_set_nonblocking();
  ssh_enter_raw_mode(-1);
}

int ssh_stdio_output_filter(SshBuffer *data,
                            size_t offset,
                            Boolean eof_received,
                            void *context)
{
  size_t received_len;

  received_len = ssh_buffer_len(data) - offset;

  return SSH_FILTER_ACCEPT(received_len);
}

int ssh_stdio_input_filter(SshBuffer *data,
                           size_t offset, 
                           Boolean eof_received,
                           void *context)
{
  size_t received_len;
  unsigned char *ucp;
  int i, c, e;

  if (!context)
      return SSH_FILTER_SHORTCIRCUIT;
  e = *((unsigned char *)context);
  if (!e)
      return SSH_FILTER_SHORTCIRCUIT;
  /* Compute the start and length of data that we have in the filter. */
  ucp = ssh_buffer_ptr(data);
  ucp += offset;
  received_len = ssh_buffer_len(data) - offset;

  for (i = 0; i < received_len; i++) {
    c = ucp[i];
    switch (stdio_filter_state) {
    case STATE_BASIC:
        if ((c == '\n') || (c == '\r'))
            stdio_filter_state = STATE_HAVE_CR;
        break;
    case STATE_HAVE_CR:
        if (c == e) {
            stdio_filter_state = STATE_HAVE_ESC;
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
        } else {
            if ((c != '\n') && (c != '\r'))
                stdio_filter_state = STATE_BASIC;
        }
        break;
    case STATE_HAVE_ESC:
        switch (c) {
        case '?':
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            ssh_escape_char_help(e);
            break;
        case '.':
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            ssh_escape_char_quit(e);
            break;
        case '&':
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            ssh_escape_char_background(e);
            break;
        case 26: /* ^Z */
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            ssh_escape_char_suspend(e);
            break;
        case '#':
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            ssh_escape_char_list_connections(e);
            break;
        case '-':
            ssh_buffer_consume_middle(data, offset + i, 1);
            received_len--; /* Buffer is now shorter    */
            i--;            /* Re-exam current position */
            return SSH_FILTER_SHORTCIRCUIT;
        default:
            if (c != e) {
                ssh_buffer_consume_middle(data, offset + i, 1);
                received_len--; /* Buffer is now shorter    */
                i--;            /* Re-exam current position */
            }
            break;
        }
        stdio_filter_state = STATE_BASIC;
        break;
    default:
        ssh_fatal("Unknown state in stdio filter.");
    }
  }

  return SSH_FILTER_ACCEPT(received_len);
}

void ssh_stdio_filter_destroy(void *context)
{
    return;
}
