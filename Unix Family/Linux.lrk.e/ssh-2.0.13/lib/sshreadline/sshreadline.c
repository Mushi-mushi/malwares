/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshreadline
 *        $Source: /ssh/CVS/src/lib/sshreadline/sshreadline.c,v $
 *        $Author: tmo $
 *
 *        Creation          : 19:47 Mar 12 1997 kivinen
 *        Last Modification : 18:07 Oct  8 1998 kivinen
 *        Last check in     : $Date: 1999/05/06 08:17:59 $
 *        Revision number   : $Revision: 1.17 $
 *        State             : $State: Exp $
 *        Version           : 1.665
 *
 *        Description       : Readline library
 *
 *
 *        $Log: sshreadline.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshreadline.h"
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_TERMIO_H
#include <termio.h>
#endif
#ifdef HAVE_CURSES_H
#include <curses.h>
#endif
#ifdef HAVE_TERMCAP_H
# include <termcap.h>
#else /* HAVE_TERMCAP_H */
# ifdef HAVE_USR_XPG4_INCLUDE_TERM_H
#  include </usr/xpg4/include/term.h>
# else /* HAVE_USR_XPG4_INCLUDE_TERM_H */
#  ifdef HAVE_TERM_H
#   include <term.h>
#  endif
# endif /* HAVE_USR_XPG4_INCLUDE_TERM_H */
#endif /* HAVE_TERMCAP_H */
#include <sys/ioctl.h>

#include "sshstream.h"
#include "sshunixfdstream.h"

#define SSH_READLINE_MAX_UNDO_DEPTH 256

typedef enum {
  SSH_RL_WORD, SSH_RL_SENTENCE
} ReadLineUnit;

typedef enum {
  SSH_RL_BACKWARD, SSH_RL_FORWARD
} ReadLineDirection;

typedef struct TermRec {
  char *term_type;              /* Terminal type */
  char *term_buffer;            /* Termcap buffer */
  int term_auto_margin;         /* am */
  unsigned char *term_clear_to_end_of_line; /* ce */
  unsigned char *term_set_cursor_column; /* ch(n) */
  unsigned char *term_delete_n_chars;   /* DC(n) */
  unsigned char *term_delete_char;      /* dc */
  unsigned char *term_insert_n_chars;   /* IC(n) */
  unsigned char *term_insert_char;      /* ic */
  unsigned char *term_move_cursor_down_n; /* DO(n) */
  unsigned char *term_move_cursor_down; /* do */
  unsigned char *term_move_cursor_left_n; /* LE(n) */
  unsigned char *term_move_cursor_left; /* le */
  unsigned char *term_move_cursor_right_n; /* RI(n) */
  unsigned char *term_move_cursor_right; /* nd */
  unsigned char *term_move_cursor_up_n; /* UP(n) */
  unsigned char *term_move_cursor_up;   /* up */
  unsigned char *key_down_arrow;                /* kd */
  unsigned char *key_left_arrow;                /* kl */
  unsigned char *key_right_arrow;       /* kr */
  unsigned char *key_up_arrow;          /* ku */
} Term;

Term *ssh_last_term = NULL;

typedef enum {
  SSH_READLINE_NORMAL_KEYMAP,
  SSH_READLINE_CTRL_X_KEYMAP,
  SSH_READLINE_ESC_KEYMAP
} ReadLineKeyMap;

typedef struct ReadLineRec {
  int fd;
  const unsigned char *prompt;
  int prompt_len;
  unsigned char *line;
  int line_alloc;
  unsigned char *display_line;
  struct termios term;
  int fcntl_flags;
  unsigned char *yank;
  unsigned char **undo;
  int *undo_cursors;
  int max_undo_depth;
  int undo_length;
  int undo_position;
  int undo_direction;
  int cursor;
  int display_cursor;
  int row_length;
  int end;
  int mark;
  int last_command_cut;
  ReadLineKeyMap keymap;
  Term *tc;
  Boolean eloop;
  SshStream stream;
  SshRLCallback callback;
} ReadLine;

/*
 * Set tty to raw mode. Return old flags in store_old_term.
 * Return 0 if success and -1 if failure.
 */
int ssh_rl_set_tty_modes(ReadLine *rl)
{
  struct termios new_term;
  struct winsize win;

  /* Set tty modes */
  if (tcgetattr(rl->fd, &rl->term) < 0)
    {
      ssh_warning("Warning: tcgetattr failed in ssh_rl_set_tty_modes: %.200s",
                  strerror(errno));
      return -1;
    }
  new_term = rl->term;
  new_term.c_iflag &= ~(ISTRIP);
  new_term.c_oflag &= ~(ONLCR);
  new_term.c_lflag &= ~(ECHO | ICANON | ISIG);
  new_term.c_cc[VMIN] = 1;
  new_term.c_cc[VTIME] = 1;
  if (tcsetattr(rl->fd, TCSAFLUSH, &new_term) < 0)
    {
      ssh_warning("Warning: tcsetattr failed in ssh_rl_set_tty_modes: %.200s",
                  strerror(errno));
      return -1;
    }
  rl->fcntl_flags = fcntl(rl->fd, F_GETFL, 0);
#ifdef O_ASYNC
  fcntl(rl->fd, F_SETFL, rl->fcntl_flags & ~(O_ASYNC | O_NONBLOCK));
#else
  fcntl(rl->fd, F_SETFL, rl->fcntl_flags & ~(O_NONBLOCK));
#endif

  if (ioctl(rl->fd, TIOCGWINSZ, &win) != -1)
    {
      rl->row_length = win.ws_col;
    }
  if (rl->row_length == 0)
    {
      rl->row_length = 80;
    }

  return 0;
}

/*
 * Restore terminal modes
 * Return 0 if success and -1 if failure.
 */
int ssh_rl_restore_tty_modes(ReadLine *rl)
{
  fcntl(rl->fd, F_SETFL, rl->fcntl_flags);

  if (tcsetattr(rl->fd, TCSAFLUSH, &rl->term) < 0)
    {
      ssh_warning("Warning: tcsetattr failed in ssh_rl_restore_tty_modes: %.200s",
                  strerror(errno));
      return -1;
    }
  return 0;
}

/*
 * Store undo information
 */
void ssh_rl_store_undo(ReadLine *rl)
{
  if (rl->undo_length == rl->max_undo_depth)
    {
      ssh_xfree(rl->undo[0]);
      memmove(rl->undo, rl->undo + 1, sizeof(const unsigned char *) *
              rl->max_undo_depth - 1);
      memmove(rl->undo_cursors, rl->undo_cursors + 1, sizeof(int) *
              rl->max_undo_depth - 1);
      rl->undo_length--;
    }
  rl->line[rl->end] = '\0';
  rl->undo[rl->undo_length] = ssh_xstrdup(rl->line);
  rl->undo_cursors[rl->undo_length] = rl->cursor;
  rl->undo_length++;
  rl->undo_position = -1;
  rl->undo_direction = -1;
}

/*
 * Enlarge line buffer so it can hold length characters
 */
void ssh_rl_enlarge_to(ReadLine *rl, int length)
{
  if (rl->line_alloc > length)
    return;

  rl->line_alloc = length + 10;
  rl->line = ssh_xrealloc(rl->line, rl->line_alloc);
  rl->display_line = ssh_xrealloc(rl->display_line, rl->line_alloc);
}

/*
 * Send string to terminal
 */
void ssh_rl_send_string(ReadLine *rl, const unsigned char *txt,
                        int len)
{
  if (write(rl->fd, txt, len) != len)
    {
      ssh_warning("Warning: write failed in ssh_rl_send_string: %.200s",
                  strerror(errno));
    }
}

/*
 * Send termcap code
 */
void ssh_rl_send_code(ReadLine *rl, const unsigned char *code)
{
  ssh_rl_send_string(rl, code, strlen((const char *) code));
}

/*
 * Send termcap code, with numeric argument
 */
void ssh_rl_send_code_n(ReadLine *rl, const unsigned char *code,
                        int n)
{
  unsigned char buffer[256];
  const char *fmt;
  int i;

  /* Skip padding */
  for( ; *code && isdigit(*code); code++)
    ;
  if (*code == '.')             /* one decimal place */
    code++;
  if (*code == '*')             /* Multiple by cnt */
    code++;

  i = 0;
  for(; *code; code++)
    {
      switch (*code)
        {
        case '%':
          code++;
          switch (*code)
            {
            case '%':
              buffer[i++] = '%';
              break;
            case 'd':
              fmt = "%d";
              goto format;
            case '2':
              fmt = "%02d";
              goto format;
            case '3':
              fmt = "%03d";
              goto format;
            case '+':
              code++;
              n += *code;
              /*FALLTHROUGH*/
            case '.':
              fmt = "%c";
            format:
              snprintf((char *) (buffer + i), sizeof(buffer) - i, fmt, n);
              i = strlen((char *) buffer);
              break;
            case '>':
              code++;
              if(n > *code)
                n += *(code + 1);
              code++;
              break;
            case 'r':
              /* Ignored, because we only have one arg */
              break;
            case 'i':
              n++;
              break;
            case 'n':
              n ^= 0140;
              break;
            case 'B':
              n = (16 * (n / 10)) + (n % 10);
              break;
            case 'D':
              n = (n - 2 * (n % 16));
              break;
            }
          break;
        default:
          buffer[i++] = *code;
          break;
        }
      if (i > 200)
        {
          ssh_rl_send_string(rl, buffer, i);
          i = 0;
        }
    }
  ssh_rl_send_string(rl, buffer, i);
}

/*
 * Move cursor to correct place
 */
void ssh_rl_move_cursor(ReadLine *rl, int new_pos)
{
  int cursor_row, new_row, cursor_column, new_column;
  int i;

  if (new_pos == rl->display_cursor)
    return;

  new_row = new_pos / rl->row_length;
  cursor_row = rl->display_cursor / rl->row_length;
  new_column = new_pos % rl->row_length;
  cursor_column = rl->display_cursor % rl->row_length;

  /* On different row? */
  if (new_row != cursor_row)
    {
      if (new_row < cursor_row) /* Move up on screen */
        {
          if ((cursor_row - new_row > 1 &&
               rl->tc->term_move_cursor_up_n) ||
              (rl->tc->term_move_cursor_up_n &&
               !rl->tc->term_move_cursor_up))
            {
              ssh_rl_send_code_n(rl, rl->tc->term_move_cursor_up_n,
                                 cursor_row - new_row);
            }
          else
            {
              for(i = 0; i < cursor_row - new_row; i++)
                ssh_rl_send_code(rl, rl->tc->term_move_cursor_up);
            }
        }
      else /* Move down on screen */
        {
          if ((new_row - cursor_row > 1 &&
               rl->tc->term_move_cursor_down_n) ||
              (rl->tc->term_move_cursor_down_n &&
               !rl->tc->term_move_cursor_down))
            {
              ssh_rl_send_code_n(rl, rl->tc->term_move_cursor_down_n,
                                 new_row - cursor_row);
            }
          else
            {
              for(i = 0; i < new_row - cursor_row; i++)
                ssh_rl_send_code(rl, rl->tc->term_move_cursor_down);
            }
        }
    }
  if (new_column != cursor_column)
    {
      if (rl->tc->term_set_cursor_column)
        {
          ssh_rl_send_code_n(rl, rl->tc->term_set_cursor_column,
                             new_column + 1);
        }
      else
        {
          if (new_column < cursor_column) /* Move left */
            {
              if ((cursor_column - new_column > 1 &&
                   rl->tc->term_move_cursor_left_n) ||
                  (rl->tc->term_move_cursor_left_n &&
                   !rl->tc->term_move_cursor_left))
                {
                  ssh_rl_send_code_n(rl, rl->tc->term_move_cursor_left_n,
                                     cursor_column - new_column);
                }
              else
                {
                  for(i = 0; i < cursor_column - new_column; i++)
                    ssh_rl_send_code(rl, rl->tc->term_move_cursor_left);
                }
            }
          else /* Move right */
            {
              if ((new_column - cursor_column > 1 &&
                   rl->tc->term_move_cursor_right_n) ||
                  (rl->tc->term_move_cursor_right_n &&
                   !rl->tc->term_move_cursor_right))
                {
                  ssh_rl_send_code_n(rl, rl->tc->term_move_cursor_right_n,
                                     new_column - cursor_column);
                }
              else
                {
                  for(i = 0; i < new_column - cursor_column; i++)
                    ssh_rl_send_code(rl, rl->tc->term_move_cursor_right);
                }
            }
        }
    }
  rl->display_cursor = new_pos;
}

/*
 * Write stuff to screen, fix the cursor location.
 */
void ssh_rl_write_string(ReadLine *rl, const unsigned char *txt,
                         int len)
{
  int l;

  /* If we have auto margins or text fits on one line, just send it */
  if (rl->tc->term_auto_margin ||
      (rl->display_cursor % rl->row_length) + len < rl->row_length)
    {
      ssh_rl_send_string(rl, txt, len);
      rl->display_cursor += len;
      if ((rl->display_cursor % rl->row_length) == 0)
        {
          ssh_rl_send_string(rl, (unsigned char *) " ", 1);
          if (rl->tc->term_move_cursor_left)
            ssh_rl_send_code(rl, rl->tc->term_move_cursor_left);
          else if (rl->tc->term_move_cursor_left_n)
            ssh_rl_send_code_n(rl, rl->tc->term_move_cursor_left_n, 1);
          else
            ssh_rl_send_code_n(rl, rl->tc->term_set_cursor_column, 0);
        }
    }
  else
    {
      /* Send end of line */
      l = rl->row_length - (rl->display_cursor % rl->row_length);
      ssh_rl_send_string(rl, txt, l);
      rl->display_cursor += l - 1;
      txt += l;
      len -= l;
      /* Move to next line */
      ssh_rl_move_cursor(rl, rl->display_cursor + 1);
      for(; len > rl->row_length; len -= rl->row_length)
        {
          ssh_rl_send_string(rl, txt, rl->row_length);
          rl->display_cursor += rl->row_length - 1;
          txt += rl->row_length;
          /* Move to next line */
          ssh_rl_move_cursor(rl, rl->display_cursor + 1);
        }
      ssh_rl_send_string(rl, txt, len);
      rl->display_cursor += len;
    }
}

/*
 * Redraw display
 */
void ssh_rl_redraw_display(ReadLine *rl)
{
  int common_start, common_end, line_len, display_len;
  int i;

  line_len = rl->end;
  rl->line[rl->end] = '\0';
  display_len = strlen((char *) rl->display_line);
  /* Skip common part */
  for(common_start = 0; common_start < line_len && common_start < display_len
        && rl->line[common_start] == rl->display_line[common_start];
      common_start++)
    ;
  if (common_start != line_len || common_start != display_len)
    {
      /* Find common end */
      for(common_end = 0; common_end < line_len && common_end < display_len
            && rl->line[line_len - common_end - 1]
            == rl->display_line[display_len - common_end - 1]; common_end++)
        ;
      if (common_start == line_len || common_start == display_len)
        common_end = 0;
      if (common_start + common_end > line_len)
        common_end = line_len - common_start;
      if (common_start + common_end > display_len)
        common_end = display_len - common_start;

      if (line_len < display_len) /* Some characters deleted */
        {
          /* Move cursor to start of different part */
          ssh_rl_move_cursor(rl, rl->prompt_len + common_start);

          if (line_len + rl->prompt_len < rl->row_length)
            {
              /* The line fits in one row, use delete capabilities */
              if ((display_len - line_len > 1 &&
                   rl->tc->term_delete_n_chars) ||
                  (rl->tc->term_delete_n_chars &&
                   !rl->tc->term_delete_char))
                {
                  ssh_rl_send_code_n(rl, rl->tc->term_delete_n_chars,
                                     display_len - line_len);
                }
              else if (rl->tc->term_delete_char)
                {
                  for(i = 0; i < display_len - line_len; i++)
                    ssh_rl_send_code(rl, rl->tc->term_delete_char);
                }
              else /* No terminal delete capability, draw till end of line */
                common_end = 0;
            }
          else /* More than one line, draw till end of line */
            common_end = 0;

          ssh_rl_write_string(rl, rl->line + common_start,
                              line_len - common_end - common_start);

          if (common_end == 0)
            {
              /* More than 1 line deleted */
              if (display_len - line_len > rl->row_length &&
                  rl->tc->term_clear_to_end_of_line)
                {
                  /* Clear first line */
                  ssh_rl_send_code(rl, rl->tc->term_clear_to_end_of_line);
                  for(i = ((rl->prompt_len + line_len) / rl->row_length + 1)
                        * rl->row_length;
                      i < display_len;
                      i += rl->row_length)
                    {
                      ssh_rl_move_cursor(rl, i);
                      ssh_rl_send_code(rl, rl->tc->term_clear_to_end_of_line);
                    }
                  ssh_rl_move_cursor(rl, i);
                  ssh_rl_send_code(rl, rl->tc->term_clear_to_end_of_line);
                }
              else
                {
                  /* Some junk may remain after last char */
                  if ((rl->display_cursor % rl->row_length) !=
                      rl->row_length - 1 &&
                      rl->tc->term_clear_to_end_of_line)
                    {
                      /* We are not at the end of line and clear to end of line
                         found, use it */
                      ssh_rl_send_code(rl, rl->tc->term_clear_to_end_of_line);
                    }
                  else
                    {
                      /* Either we are at the end of line, or clear to end of
                         line wasn't found. Use spaces */
                      for(i = 0; i < display_len - line_len; i += 10)
                        ssh_rl_write_string(rl, (unsigned char *) "          ",
                                            10);
                      ssh_rl_write_string(rl, (unsigned char *) "          ",
                                          (display_len - line_len + 1) % 10);
                    }
                }
            }
        }
      else if (line_len > display_len) /* Some characters inserted */
        {
          /* Move cursor to start of different part */
          ssh_rl_move_cursor(rl, rl->prompt_len + common_start);

          if (line_len + rl->prompt_len < rl->row_length)
            {
              /* The line fits in one row, use insert capabilities */
              if ((line_len - display_len > 1 &&
                   rl->tc->term_insert_n_chars) ||
                  (rl->tc->term_insert_n_chars &&
                   !rl->tc->term_insert_char))
                {
                  ssh_rl_send_code_n(rl, rl->tc->term_insert_n_chars,
                                     line_len - display_len);
                }
              else if (rl->tc->term_insert_char)
                {
                  for(i = 0; i < line_len - display_len; i++)
                    ssh_rl_send_code(rl, rl->tc->term_insert_char);
                }
              else /* No terminal insert capability, draw till end of line */
                common_end = 0;
            }
          else /* More than one line, draw till end of line */
            common_end = 0;

          ssh_rl_write_string(rl, rl->line + common_start,
                              line_len - common_end - common_start);
        }
      else                      /* Some characters replaced, draw them */
        {
          /* Move cursor to start of different part */
          ssh_rl_move_cursor(rl, rl->prompt_len + common_start);
          ssh_rl_write_string(rl, rl->line + common_start,
                              line_len - common_end - common_start);
        }
    }
  ssh_rl_move_cursor(rl, rl->prompt_len + rl->cursor);
  strcpy((char *) rl->display_line, (char *) rl->line);
}

/*
 * Find start/end of sentence/word from given direction
 */
int ssh_rl_find(ReadLine *rl, int start_pos, ReadLineUnit unit,
                 ReadLineDirection dir)
{
  int orig_place = start_pos;
  if (dir == SSH_RL_BACKWARD)
    {
      if (start_pos > 0)
        start_pos--;
      if (unit == SSH_RL_WORD)
        {
          /* Find next possible place */
          for(; start_pos > 0 && !isalnum(rl->line[start_pos]); start_pos--)
            ;
          if (start_pos == 0)
            return start_pos;
          for(; start_pos > 0 && isalnum(rl->line[start_pos]); start_pos--)
            ;
          if (!isalnum(rl->line[start_pos]))
            start_pos++;
          return start_pos;
        }

      /* Find next possible place */
      for(; start_pos > 0 && isspace(rl->line[start_pos]); start_pos--)
        ;
      if (start_pos == 0)
        return start_pos;
      while (start_pos > 0 && isspace(rl->line[start_pos]))
        start_pos--;
      while (start_pos > 0 &&
             (rl->line[start_pos] == '.' || rl->line[start_pos] == '!' ||
              rl->line[start_pos] == '?' || rl->line[start_pos] == ':'))
        start_pos--;

      for(; start_pos > 0 && rl->line[start_pos] != '.' &&
            rl->line[start_pos] != '!' && rl->line[start_pos] != '?' &&
            rl->line[start_pos] != ':'; start_pos--)
        ;
      if (rl->line[start_pos] == '.' || rl->line[start_pos] == '!' ||
          rl->line[start_pos] == '?' || rl->line[start_pos] == ':')
        {
          start_pos++;
          for(;start_pos < orig_place && isspace(rl->line[start_pos]);
              start_pos++)
            ;
        }
      return start_pos;
    }
  /* Find next possible place */
  if (unit == SSH_RL_WORD)
    {
      for(; start_pos < rl->end && !isalnum(rl->line[start_pos]); start_pos++)
        ;
      if (start_pos == rl->end)
        return start_pos;
      for(; start_pos < rl->end && isalnum(rl->line[start_pos]); start_pos++)
        ;
      return start_pos;
    }
  for(; start_pos < rl->end && isspace(rl->line[start_pos]); start_pos++)
    ;
  if (start_pos == rl->end)
    return start_pos;
  for(; start_pos < rl->end && rl->line[start_pos] != '.' &&
        rl->line[start_pos] != '!' && rl->line[start_pos] != '?' &&
        rl->line[start_pos] != ':'; start_pos++)
    ;
  while (start_pos < rl->end &&
         (rl->line[start_pos] == '.' || rl->line[start_pos] == '!' ||
          rl->line[start_pos] == '?' || rl->line[start_pos] == ':'))
    start_pos++;
  while (start_pos < rl->end && isspace(rl->line[start_pos]))
    start_pos++;
  return start_pos;
}

/*
 * Downcase character
 */
void ssh_rl_downcase(ReadLine *rl, int pos)
{
  rl->line[pos] = tolower(rl->line[pos]);
}

/*
 * Upcase character
 */
void ssh_rl_upcase(ReadLine *rl, int pos)
{
  rl->line[pos] = toupper(rl->line[pos]);
}

/*
 * Run command between two positions
 */
void ssh_rl_run(ReadLine *rl, int st, int en,
                void (*func)(ReadLine *rl, int pos))
{
  int i;

  for(i = st; i < en; i++)
    {
      (*func)(rl, i);
    }
  return;
}

/*
 * Run command on region
 */
void ssh_rl_run_region(ReadLine *rl, void (*func)(ReadLine *rl, int pos))
{
  if (rl->mark == -1)
    return;
  if (rl->mark == rl->cursor)
    return;
  ssh_rl_store_undo(rl);
  if (rl->mark < rl->cursor)
    ssh_rl_run(rl, rl->mark, rl->cursor, func);
  else
    ssh_rl_run(rl, rl->cursor, rl->mark, func);
  rl->last_command_cut = -1;
  return;
}

/*
 * Readline main loop
 */
int ssh_rl_loop(ReadLine *rl)
{
  unsigned char buffer[10];
  int ret, i, j;
  char *p;
  int tmp;
  int len, pos;
  int start1, start2, end1, end2;

  if (!rl->eloop)
    ssh_rl_store_undo(rl);

  do {
    ssh_rl_redraw_display(rl);
    ret = read(rl->fd, buffer, sizeof(buffer));
    if (ret == 0)
      return -1;

    if (ret < 0)
      {
        if (rl->eloop)
          return 1;
        else
          return -1;
      }
    for(i = 0; i < ret; i++)
      {
        if (rl->keymap == SSH_READLINE_NORMAL_KEYMAP)
          {
            switch(buffer[i])
              {
              case 000: /* Ctrl-Space: Set mark */
                rl->mark = rl->cursor;
                rl->last_command_cut = -1;
                break;
              case 001: /* Ctrl-A: Beginning of line */
                rl->cursor = 0;
                break;
              case 002: /* Ctrl-B: Backward character */
                if (rl->cursor > 0)
                  rl->cursor--;
                break;
              case 003: /* Ctrl-C: Ignored */
                ssh_rl_redraw_display(rl);
                break;
              case 004: /* Ctrl-D: Erase character right, or eof if beginning
                           of empty line. */
                if (rl->end == 0)
                  return -1;
                /* At end of line */
                if (rl->end == rl->cursor)
                  break;
                ssh_rl_store_undo(rl);
                memmove(rl->line + rl->cursor, rl->line + rl->cursor + 1,
                        rl->end - rl->cursor - 1);
                if (rl->mark == rl->cursor)
                  rl->mark = -1;
                else if (rl->mark > rl->cursor)
                  rl->mark--;
                rl->end--;
                rl->last_command_cut = -1;
                break;
              case 005: /* Ctrl-E: End of line */
                rl->cursor = rl->end;
                break;
              case 006: /* Ctrl-F: Forward character */
                if (rl->cursor != rl->end)
                  rl->cursor++;
                break;
              case 007: /* Ctrl-G: Ignored */
                break;
              case 010: /* Ctrl-H: Backspace */
              case 0177: /* Delete: Backspace */
                if (rl->cursor == 0)
                  break;
                ssh_rl_store_undo(rl);
                if (rl->cursor != rl->end)
                  memmove(rl->line + rl->cursor - 1, rl->line + rl->cursor,
                          rl->end - rl->cursor);
                if (rl->mark == rl->cursor - 1)
                  rl->mark = -1;
                else if (rl->mark > rl->cursor)
                  rl->mark--;
                rl->cursor--;
                rl->end--;
                rl->last_command_cut = -1;
                break;
              case 011: /* Ctrl-I: Tab */
                ssh_rl_store_undo(rl);
                len = (rl->cursor + rl->prompt_len) % 8;
                len = 8 - len;
                ssh_rl_enlarge_to(rl, rl->end + len);
                if (rl->end != rl->cursor)
                  memmove(rl->line + rl->cursor + len, rl->line + rl->cursor,
                          rl->end - rl->cursor);
                if (rl->mark > rl->cursor)
                  rl->mark += len;
                for(; len > 0; len--)
                  {
                    rl->line[rl->cursor] = ' ';
                    rl->end++;
                    rl->cursor++;
                  }
                rl->last_command_cut = -1;
                break;
              case 012: /* Ctrl-J: Accept line */
                return 0;
              delete_end_of_line:
              case 013: /* Ctrl-K: Delete to end of line */
                if (rl->cursor == rl->end)
                  break;
                len = rl->end - rl->cursor;
                if (rl->yank)
                  {
                    if (rl->last_command_cut == rl->end)
                      {
                        rl->yank = ssh_xrealloc(rl->yank, len +
                                                strlen((char *) rl->yank) + 1);
                        memmove(rl->yank + len, rl->yank,
                                strlen((char *) rl->yank) + 1);
                        memmove(rl->yank, rl->line + rl->cursor, len);
                      }
                    else
                      {
                        ssh_xfree(rl->yank);
                        rl->yank = ssh_xmalloc(len + 1);
                        memmove(rl->yank, rl->line + rl->cursor, len);
                        rl->yank[len] = '\0';
                      }
                  }
                else
                  {
                    rl->yank = ssh_xmalloc(len + 1);
                    memmove(rl->yank, rl->line + rl->cursor, len);
                    rl->yank[len] = '\0';
                  }

                rl->end = rl->cursor;
                if (rl->mark > rl->cursor)
                  rl->mark = -1;
                rl->last_command_cut = rl->end;
                break;
              case 014: /* Ctrl-L: Redraw line */
                memset(rl->display_line, 1, rl->end);
                ssh_rl_move_cursor(rl, 0);
                ssh_rl_write_string(rl, rl->prompt, rl->prompt_len);
                break;
              case 015: /* Ctrl-M: Accept line */
                return 0;
              case 016: /* Ctrl-N: Next line */
                if (rl->cursor <= rl->end - rl->row_length)
                  rl->cursor += rl->row_length;
                break;
              case 017: /* Ctrl-O: Ignored */
                break;
              case 020: /* Ctrl-P: Previous line */
                if (rl->cursor >= rl->row_length)
                  rl->cursor -= rl->row_length;
                break;
              case 021: /* Ctrl-Q: Ignored */
              case 022: /* Ctrl-R: Ignored */
              case 023: /* Ctrl-S: Ignored */
                break;
              case 024: /* Ctrl-T: toggle two chars */
                if (rl->cursor == 0)
                  break;
                if (rl->end <= 1)
                  break;
                if (rl->end != rl->cursor)
                  rl->cursor++;
                ssh_rl_store_undo(rl);
                tmp = rl->line[rl->cursor - 2];
                rl->line[rl->cursor - 2] = rl->line[rl->cursor - 1];
                rl->line[rl->cursor - 1] = tmp;
                rl->last_command_cut = -1;
                break;
              case 025: /* Ctrl-U: Kill line */
                ssh_rl_store_undo(rl);
                rl->cursor = 0;
                goto delete_end_of_line;
              case 026: /* Ctrl-V: Ignored */
                break;
              kill_region:
              case 027: /* Ctrl-W: kill-region */
                /* Mark not set kill word */
                if (rl->mark == -1 || rl->mark > rl->end)
                  {
                    if (rl->cursor == 0)
                      break;
                    j = rl->cursor;

                    /* Skip whitespace */
                    if (isspace(rl->line[j - 1]))
                      for(; j > 0; j--)
                        if (!isspace(rl->line[j - 1]))
                          break;

                    /* If the next char is alphanumeric, remove all
                       alphanumeric characters */
                    if (isalnum(rl->line[j - 1]))
                      {
                        for(; j > 0; j--)
                          if (!isalnum(rl->line[j - 1]))
                            break;
                      }
                    else   /* If the next char is not alphanumeric
                              remove up to next whitespace. */
                      {
                        for(; j > 0; j--)
                          if (isspace(rl->line[j - 1]))
                            break;
                      }
                    rl->mark = j;
                  }
                if (rl->mark == rl->cursor)
                  break;
                ssh_rl_store_undo(rl);
                if (rl->mark < rl->cursor)
                  {
                    pos = rl->mark;
                    rl->mark = rl->cursor;
                    rl->cursor = pos;
                  }
                len = rl->mark - rl->cursor;
                if (rl->yank)
                  {
                    if (rl->last_command_cut == rl->mark)
                      {
                        rl->yank = ssh_xrealloc(rl->yank, len +
                                                strlen((char *) rl->yank) + 1);
                        memmove(rl->yank + len, rl->yank,
                                strlen((char *) rl->yank) + 1);
                        memmove(rl->yank, rl->line + rl->cursor, len);
                      }
                    else if (rl->last_command_cut == rl->cursor)
                      {
                        rl->yank = ssh_xrealloc(rl->yank, len +
                                                strlen((char *) rl->yank) + 1);
                        rl->yank[strlen((char *) rl->yank) + len] = '\0';
                        memmove(rl->yank + strlen((char *) rl->yank),
                                rl->line + rl->cursor, len);
                      }
                    else
                      {
                        ssh_xfree(rl->yank);
                        rl->yank = ssh_xmalloc(len + 1);
                        memmove(rl->yank, rl->line + rl->cursor, len);
                        rl->yank[len] = '\0';
                      }
                  }
                else
                  {
                    rl->yank = ssh_xmalloc(len + 1);
                    memmove(rl->yank, rl->line + rl->cursor, len);
                    rl->yank[len] = '\0';
                  }

                memmove(rl->line + rl->cursor, rl->line + rl->mark,
                        rl->end - rl->mark);
                rl->end -= len;
                rl->mark = -1;
                rl->last_command_cut = rl->cursor;
                break;
              case 030: /* Ctrl-X: extended command map */
                rl->keymap = SSH_READLINE_CTRL_X_KEYMAP;
                break;
              case 031: /* Ctrl-Y: yank */
                ssh_rl_store_undo(rl);
                len = strlen((char *) rl->yank);
                ssh_rl_enlarge_to(rl, rl->end + len);
                memmove(rl->line + rl->cursor + len, rl->line + rl->cursor,
                        rl->end - rl->cursor);
                memmove(rl->line + rl->cursor, rl->yank, len);
                rl->mark = rl->cursor;
                rl->end += len;
                rl->cursor += len;
                rl->last_command_cut = -1;
                break;
              case 032: /* Ctrl-Z: Ignored */
                break;
              case 033: /* Ctrl-[: Esc comamnd map */
                rl->keymap = SSH_READLINE_ESC_KEYMAP;
                break;
              case 034: /* Ctrl-\: Ignored */
                break;
              case 035: /* Ctrl-]: Ignored */
                break;
              case 036: /* Ctrl-^: Ignored */
                break;
              undo:
              case 037: /* Ctrl-_: Undo */
                if (rl->undo_position == -1)
                  {
                    ssh_rl_store_undo(rl);
                    rl->undo_position = rl->undo_length - 1;
                    rl->undo_direction = -1;
                  }
                rl->undo_position += rl->undo_direction;
                if (rl->undo_position == 0)
                  {
                    rl->undo_direction = 1;
                  }
                else if (rl->undo_position >= rl->undo_length - 1)
                  {
                    rl->undo_direction = -1;
                  }
                rl->cursor = rl->undo_cursors[rl->undo_position];
                ssh_rl_enlarge_to(rl, strlen((char *)
                                             rl->undo[rl->undo_position]));
                strcpy((char *) rl->line,
                       (char *) rl->undo[rl->undo_position]);
                rl->end = strlen((char *) rl->line);
                rl->mark = -1;
                rl->last_command_cut = -1;
                break;
              case 0200: case 0201: case 0202: case 0203:
              case 0204: case 0205: case 0206: case 0207:
              case 0210: case 0211: case 0212: case 0213:
              case 0214: case 0215: case 0216: case 0217:
              case 0220: case 0221: case 0222: case 0223:
              case 0224: case 0225: case 0226: case 0227:
              case 0230: case 0231: case 0232: case 0233:
              case 0234: case 0235: case 0236: case 0237:
                buffer[i] &= 0x7f;
                goto esc_map;
                break;
              insert_char:
              default:
                ssh_rl_enlarge_to(rl, rl->end + 1);
                if (rl->end != rl->cursor)
                  memmove(rl->line + rl->cursor + 1, rl->line + rl->cursor,
                          rl->end - rl->cursor);
                rl->line[rl->cursor] = buffer[i];
                if (rl->mark > rl->cursor)
                  rl->mark++;
                rl->end++;
                rl->cursor++;
                rl->last_command_cut = -1;
                if (buffer[i] == ' ')
                  ssh_rl_store_undo(rl);
                break;
              }
          }
        else if (rl->keymap == SSH_READLINE_CTRL_X_KEYMAP)
          {
            rl->keymap = SSH_READLINE_NORMAL_KEYMAP;
            switch(buffer[i])
              {
              case 003: /* Ctrl-X Ctrl-C: Exit */
                return 0;
              case 014: /* Ctrl-X Ctrl-L: Downcase region */
                ssh_rl_run_region(rl, ssh_rl_downcase);
                break;
              case 025: /* Ctrl-X Ctrl-U: Upcase region */
                ssh_rl_run_region(rl, ssh_rl_upcase);
                break;
              case 030: /* Ctrl-X Ctrl-X: Exchange point and mark */
                if (rl->mark == -1)
                  break;
                pos = rl->mark;
                rl->mark = rl->cursor;
                rl->cursor = pos;
                break;
              case 'h': /* Ctrl-X h: Mark whole buffer */
                rl->mark = 0;
                rl->cursor = rl->end;
                break;
              case 'u': /* Ctrl-X u: Undo */
                goto undo;
              default:
                break;
              }
          }
        else if (rl->keymap == SSH_READLINE_ESC_KEYMAP)
          {
          esc_map:
            rl->keymap = SSH_READLINE_NORMAL_KEYMAP;
            switch(buffer[i])
              {
              case 010: /* Esc Ctrl-h: Kill word backward */
              case 0177: /* Esc del: Kill word backward */
                rl->mark = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                       SSH_RL_BACKWARD);
                goto kill_region;
              case ' ': /* Esc Spc: Just one space */
              case '\\':/* Esc \\: delete spaces */
                if (!isspace(rl->line[rl->cursor]) &&
                    (rl->cursor == 0 || !isspace(rl->line[rl->cursor - 1])))
                  {
                    if (buffer[i] == ' ')
                      goto insert_char;
                    break;
                  }
                ssh_rl_store_undo(rl);
                if (rl->cursor > 0 && isspace(rl->line[rl->cursor - 1]))
                  rl->cursor--;
                tmp = rl->cursor;
                for(; rl->cursor > 0 && isspace(rl->line[rl->cursor]);
                    rl->cursor--)
                  ;
                if (isspace(rl->line[rl->cursor]))
                  rl->cursor++;
                else
                  rl->cursor += 2;
                if (buffer[i] == '\\')
                  rl->cursor--;
                for(; tmp < rl->end && isspace(rl->line[tmp]); tmp++)
                  ;
                memmove(rl->line + rl->cursor, rl->line + tmp,
                        rl->end - tmp);
                rl->end -= (tmp - rl->cursor);
                if (rl->mark >= rl->cursor &&
                    rl->mark <= tmp)
                  rl->mark = -1;
                else if (rl->mark > tmp)
                  rl->mark -= (tmp - rl->cursor);
                rl->last_command_cut = -1;
                break;
              case '<': /* Esc <: Beginning of buffer */
                rl->cursor = 0;
                break;
              case '>': /* Esc >: End of buffer */
                rl->cursor = rl->end;
                break;
              case '@': /* Esc @: Mark word */
                rl->mark = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                       SSH_RL_FORWARD);
                break;
              case 'a': /* Esc A: Backward sentence */
                rl->cursor = ssh_rl_find(rl, rl->cursor, SSH_RL_SENTENCE,
                                         SSH_RL_BACKWARD);
                break;
              case 'b': /* Esc B: Backward word */
                rl->cursor = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                         SSH_RL_BACKWARD);
                break;
              case 'c': /* Esc C: Capitalize word */
                pos = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD, SSH_RL_FORWARD);
                len = ssh_rl_find(rl, pos, SSH_RL_WORD, SSH_RL_BACKWARD);
                if (len < rl->cursor)
                  {
                    len = rl->cursor;
                  }
                ssh_rl_store_undo(rl);
                rl->line[len] = toupper(rl->line[len]);
                rl->last_command_cut = -1;
                rl->cursor = pos;
                break;
              case 'd': /* Esc D: Kill word */
                rl->mark = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                       SSH_RL_FORWARD);
                goto kill_region;
              case 'e': /* Esc e: Forward sentence */
                rl->cursor = ssh_rl_find(rl, rl->cursor, SSH_RL_SENTENCE,
                                         SSH_RL_FORWARD);
                break;
              case 'f': /* Esc f: Forward word */
                rl->cursor = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                         SSH_RL_FORWARD);
                break;
              case 'k': /* Esc k: Kill sentence */
                rl->mark = ssh_rl_find(rl, rl->cursor, SSH_RL_SENTENCE,
                                       SSH_RL_FORWARD);
                goto kill_region;
              case 'l': /* Esc l: Lowercase word */
                ssh_rl_store_undo(rl);
                pos = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD, SSH_RL_FORWARD);
                ssh_rl_run(rl, rl->cursor, pos, ssh_rl_downcase);
                rl->cursor = pos;
                rl->last_command_cut = -1;
                break;
              case 't': /* Esc t: Transpose words */
                ssh_rl_store_undo(rl);
                start1 = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD,
                                     SSH_RL_BACKWARD);
                end1 = ssh_rl_find(rl, start1, SSH_RL_WORD,
                                   SSH_RL_FORWARD);
                end2 = ssh_rl_find(rl, end1, SSH_RL_WORD, SSH_RL_FORWARD);
                start2 = ssh_rl_find(rl, end2, SSH_RL_WORD, SSH_RL_BACKWARD);
                if (start1 == start2)
                  {
                    start1 = ssh_rl_find(rl, start2, SSH_RL_WORD,
                                         SSH_RL_BACKWARD);
                    end1 = ssh_rl_find(rl, start1, SSH_RL_WORD,
                                       SSH_RL_FORWARD);
                  }
                if (start1 == start2)
                  break;
                p = ssh_xmalloc(start2 - start1);
                memmove(p, rl->line + start1, start2 - start1);
                memmove(rl->line + start1, rl->line + start2, end2 - start2);
                memmove(rl->line + start1 + end2 - start2,
                        p + end1 - start1, start2 - end1);
                memmove(rl->line + end2 - (end1 - start1),
                        p, end1 - start1);
                rl->last_command_cut = -1;
                rl->cursor = end2;
                break;
              case 'u': /* Esc u: Uppercase word */
                ssh_rl_store_undo(rl);
                pos = ssh_rl_find(rl, rl->cursor, SSH_RL_WORD, SSH_RL_FORWARD);
                ssh_rl_run(rl, rl->cursor, pos, ssh_rl_upcase);
                rl->cursor = pos;
                rl->last_command_cut = -1;
                break;
              }
          }
      }
  } while (rl->eloop == FALSE);

  if (rl->eloop)
    ssh_rl_redraw_display(rl);

  return 1;
}

/*
 * Initialize termcap entries
 */
void ssh_rl_initialize_termcap(ReadLine *rl)
{
  char tcbuffer[1024], *term, *term_buffer_ptr;
  Boolean use_builtin = FALSE;

  if (ssh_last_term == NULL)
    {
      ssh_last_term = ssh_xmalloc(sizeof(Term));
      ssh_last_term->term_buffer = ssh_xmalloc(1024);
      ssh_last_term->term_type = NULL;
    }
  term = (char *)getenv("TERM");
  if (term == NULL)
    {
      ssh_last_term->term_type = term;
      use_builtin = TRUE;
    }
  else if (term != ssh_last_term->term_type)
    {
      if (tgetent(tcbuffer, term) < 0)
        {
          ssh_warning("Warning: No termcap entry for `%.50s' found, using vt100",
                      term);
          use_builtin = TRUE;
          ssh_last_term->term_type = term;
        }
      else
        {
          ssh_last_term->term_type = term;
          term_buffer_ptr = ssh_last_term->term_buffer;
          ssh_last_term->term_auto_margin = tgetflag("am");;
          ssh_last_term->term_clear_to_end_of_line = (unsigned char *)
            tgetstr("ce", &term_buffer_ptr);
          ssh_last_term->term_set_cursor_column = (unsigned char *)
            tgetstr("ch", &term_buffer_ptr);
          ssh_last_term->term_delete_n_chars = (unsigned char *)
            tgetstr("DC", &term_buffer_ptr);
          ssh_last_term->term_delete_char = (unsigned char *)
            tgetstr("dc", &term_buffer_ptr);
          ssh_last_term->term_insert_n_chars = (unsigned char *)
            tgetstr("IC", &term_buffer_ptr);
          ssh_last_term->term_insert_char = (unsigned char *)
            tgetstr("ic", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_down_n = (unsigned char *)
            tgetstr("DO", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_down = (unsigned char *)
            tgetstr("do", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_left_n = (unsigned char *)
            tgetstr("LE", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_left = (unsigned char *)
            tgetstr("le", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_right_n = (unsigned char *)
            tgetstr("RI", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_right = (unsigned char *)
            tgetstr("nd", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_up_n = (unsigned char *)
            tgetstr("UP", &term_buffer_ptr);
          ssh_last_term->term_move_cursor_up = (unsigned char *)
            tgetstr("up", &term_buffer_ptr);
          ssh_last_term->key_down_arrow = (unsigned char *)
            tgetstr("kd", &term_buffer_ptr);
          ssh_last_term->key_left_arrow = (unsigned char *)
            tgetstr("kl", &term_buffer_ptr);
          ssh_last_term->key_right_arrow = (unsigned char *)
            tgetstr("kr", &term_buffer_ptr);
          ssh_last_term->key_up_arrow = (unsigned char *)
            tgetstr("ku", &term_buffer_ptr);
          if ((!ssh_last_term->term_move_cursor_up &&
               !ssh_last_term->term_move_cursor_up_n) ||
              (!ssh_last_term->term_move_cursor_down &&
               !ssh_last_term->term_move_cursor_down_n) ||
              (!ssh_last_term->term_set_cursor_column &&
               ((!ssh_last_term->term_move_cursor_left &&
                 !ssh_last_term->term_move_cursor_left_n) ||
                (!ssh_last_term->term_move_cursor_right &&
                 !ssh_last_term->term_move_cursor_right_n))))
            {
              ssh_warning("Warning: Need basic cursor movement capablity, using vt100");
              use_builtin = TRUE;
            }
        }
    }
  if (use_builtin)
    {
      /* Built-in VT100 */
      ssh_last_term->term_auto_margin = 1;
      ssh_last_term->term_clear_to_end_of_line = (unsigned char *) "\x1b[K";
      ssh_last_term->term_set_cursor_column = NULL;
      ssh_last_term->term_delete_n_chars = NULL;
      ssh_last_term->term_delete_char = NULL;
      ssh_last_term->term_insert_n_chars = NULL;
      ssh_last_term->term_insert_char = NULL;
      ssh_last_term->term_move_cursor_down_n = (unsigned char *) "\x1b[%dB";
      ssh_last_term->term_move_cursor_down = (unsigned char *) "\x1b[B";
      ssh_last_term->term_move_cursor_left_n = (unsigned char *) "\x1b[%dD";
      ssh_last_term->term_move_cursor_left = (unsigned char *) "\x1b[D";
      ssh_last_term->term_move_cursor_right_n = (unsigned char *) "\x1b[%dC";
      ssh_last_term->term_move_cursor_right = (unsigned char *) "\x1b[C";
      ssh_last_term->term_move_cursor_up_n = (unsigned char *) "\x1b[%dA";
      ssh_last_term->term_move_cursor_up = (unsigned char *) "\x1b[A";
      ssh_last_term->key_down_arrow = (unsigned char *) "\x1bOB";
      ssh_last_term->key_left_arrow = (unsigned char *) "\x1bOD";
      ssh_last_term->key_right_arrow = (unsigned char *) "\x1bOC";
      ssh_last_term->key_up_arrow = (unsigned char *) "\x1bOA";
    }
  rl->tc = ssh_last_term;
}



void iocb(SshStreamNotification notify, void *context)
{
  ReadLine *rl = (ReadLine *)context;
  int lr, rm, i;

  switch (notify)
    {
    case SSH_STREAM_DISCONNECTED:
      goto disconnect;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_rl_redraw_display(rl);
      break;

    case SSH_STREAM_INPUT_AVAILABLE:
      if ((lr = ssh_rl_loop(rl)) <= 0)
        {
          rm = ssh_rl_restore_tty_modes(rl);

          if ((lr < 0) || (rm < 0))
            {
            disconnect:
              for(i = 0; i < rl->undo_length; i++)
                ssh_xfree(rl->undo[i]);
              rl->undo_length = 0;
              if (rl->yank != NULL)
                ssh_xfree(rl->yank);
              ssh_xfree(rl->undo); rl->undo = NULL;
              ssh_xfree(rl->undo_cursors); rl->undo_cursors = NULL;
              ssh_xfree(rl->line);
              if (rl->callback)
                (*rl->callback)(rl->fd, NULL);
              ssh_rl_redraw_display(rl);
              ssh_xfree(rl);
              return;
            }
          for(i = 0; i < rl->undo_length; i++)
            ssh_xfree(rl->undo[i]);
          rl->undo_length = 0;
          if (rl->yank != NULL)
            ssh_xfree(rl->yank);
          ssh_xfree(rl->undo); rl->undo = NULL;
          ssh_xfree(rl->undo_cursors); rl->undo_cursors = NULL;
          rl->line[rl->end] = '\0';
          ssh_stream_destroy(rl->stream);
          if (rl->callback)
            (*rl->callback)(rl->fd, rl->line);
          ssh_rl_redraw_display(rl);
          ssh_xfree(rl->line);
          ssh_xfree(rl);
        }
      else
        ssh_stream_set_callback(rl->stream, iocb, (void *)rl);
      break;
    }
}


int ssh_readline_eloop(const unsigned char *prompt,
                       const unsigned char *def,
                       int fd,
                       SshRLCallback callback)
{
  ReadLine *rl;
  const unsigned char *tmp, *nl, *cr;

  rl = ssh_xcalloc(1, sizeof(ReadLine));

  rl->callback = callback;
  rl->eloop = TRUE;
  rl->fd = fd;
  rl->mark = -1;
  rl->last_command_cut = 0;
  rl->yank = NULL;
  rl->keymap = SSH_READLINE_NORMAL_KEYMAP;
  rl->max_undo_depth = SSH_READLINE_MAX_UNDO_DEPTH;
  rl->undo = ssh_xcalloc(rl->max_undo_depth, sizeof(char *));
  rl->undo_cursors = ssh_xcalloc(rl->max_undo_depth, sizeof(int));
  rl->undo[0] = ssh_xstrdup("");
  rl->undo_cursors[0] = 0;
  rl->undo_length = 1;
  rl->undo_position = 0;
  rl->undo_direction = -1;
  rl->row_length = 80;
  if (prompt == NULL)
    prompt = (unsigned char *) "";
  rl->prompt = prompt;
  tmp = (unsigned char *) strrchr((const char *) rl->prompt, '\n');
  if (tmp != NULL)
    rl->prompt = tmp + 1;
  tmp = (unsigned char *) strrchr((const char *) rl->prompt, '\r');
  if (tmp != NULL)
    rl->prompt = tmp + 1;
  rl->prompt_len = strlen((char *) rl->prompt);

  ssh_rl_initialize_termcap(rl);
  if (ssh_rl_set_tty_modes(rl) < 0)
    {
      ssh_xfree(rl->undo_cursors);
      ssh_xfree(rl->undo);
      ssh_xfree(rl);
      return -1;
    }

  rl->display_cursor = 0;
  tmp = prompt;
  while (1)
    {
      nl = (unsigned char *) strchr((const char *) tmp, '\n');
      cr = (unsigned char *) strchr((const char *) tmp, '\r');
      if (nl == NULL && cr == NULL)
        break;
      if (nl != NULL && cr != NULL)
        {
          if (nl < cr)
            cr = NULL;
          else
            nl = NULL;
        }
      if (nl != NULL)
        {
          ssh_rl_write_string(rl, tmp, nl - tmp);
          ssh_rl_send_string(rl, (unsigned char *) "\r\n", 2);
          rl->display_cursor = 0;
          tmp = nl + 1;
          if (*tmp == '\r')
            tmp++;
        }
      else
        {
          ssh_rl_write_string(rl, tmp, cr - tmp);
          if (*(cr + 1) == '\n')
            {
              ssh_rl_send_string(rl, (unsigned char *) "\r\n", 2);
              cr++;
            }
          else
            ssh_rl_send_string(rl, (unsigned char *) "\r", 1);
          rl->display_cursor = 0;
          tmp = cr + 1;
        }
    }
  ssh_rl_write_string(rl, tmp, rl->prompt_len);

  if (def)
    {
      rl->line_alloc = strlen(def) + 1;
      rl->line = ssh_xstrdup(def);
    }
  else
    {
      rl->line_alloc = 80;
      rl->line = ssh_xmalloc(rl->line_alloc);
      rl->line[0] = '\0';
    }

  rl->display_line = ssh_xmalloc(rl->line_alloc);
  rl->display_line[0] = '\0';
  rl->end = rl->cursor = strlen((char *) rl->line);

  rl->stream = ssh_stream_fd_wrap(fd, FALSE);
  ssh_stream_set_callback(rl->stream, iocb, (void *)rl);

  return 0;
}

/*
 * Read line from user. The tty at file descriptor FD is put to raw
 * mode and data is read until CR is received. The PROMPT is used to prompt
 * the input. LINE is pointer to char pointer and it should either contain
 * NULL or the mallocated string for previous value (that string is freed).
 * If line can be successfully read the LINE argument contains the
 * new mallocated string.
 *
 * The ssh_readline will return the number of characters returned in line
 * buffer. If eof or other error is noticed the return value is -1.
 */
int ssh_readline(const unsigned char *prompt,
                 unsigned char **line,
                 int fd)
{
  ReadLine *rl;
  int i;
  int lr, rm;
  const unsigned char *tmp, *nl, *cr;

  if (line == NULL)
    ssh_fatal("Fatal: ssh_readline LINE is NULL");

  rl = ssh_xcalloc(1, sizeof(ReadLine));

  rl->eloop = FALSE;
  rl->fd = fd;
  rl->mark = -1;
  rl->last_command_cut = 0;
  rl->yank = NULL;
  rl->keymap = SSH_READLINE_NORMAL_KEYMAP;
  rl->max_undo_depth = SSH_READLINE_MAX_UNDO_DEPTH;
  rl->undo = ssh_xcalloc(rl->max_undo_depth, sizeof(char *));
  rl->undo_cursors = ssh_xcalloc(rl->max_undo_depth, sizeof(int));
  rl->undo[0] = ssh_xstrdup("");
  rl->undo_cursors[0] = 0;
  rl->undo_length = 1;
  rl->undo_position = 0;
  rl->undo_direction = -1;
  rl->row_length = 80;
  if (prompt == NULL)
    prompt = (unsigned char *) "";
  rl->prompt = prompt;
  tmp = (unsigned char *) strrchr((const char *) rl->prompt, '\n');
  if (tmp != NULL)
    rl->prompt = tmp + 1;
  tmp = (unsigned char *) strrchr((const char *) rl->prompt, '\r');
  if (tmp != NULL)
    rl->prompt = tmp + 1;
  rl->prompt_len = strlen((char *) rl->prompt);

  ssh_rl_initialize_termcap(rl);
  if (ssh_rl_set_tty_modes(rl) < 0)
    {
      ssh_xfree(rl->undo_cursors);
      ssh_xfree(rl->undo);
      ssh_xfree(rl);
      if (*line != NULL)
        ssh_xfree(*line);
      *line = NULL;
      return -1;
    }

  rl->display_cursor = 0;
  tmp = prompt;
  while (1)
    {
      nl = (unsigned char *) strchr((const char *) tmp, '\n');
      cr = (unsigned char *) strchr((const char *) tmp, '\r');
      if (nl == NULL && cr == NULL)
        break;
      if (nl != NULL && cr != NULL)
        {
          if (nl < cr)
            cr = NULL;
          else
            nl = NULL;
        }
      if (nl != NULL)
        {
          ssh_rl_write_string(rl, tmp, nl - tmp);
          ssh_rl_send_string(rl, (unsigned char *) "\r\n", 2);
          rl->display_cursor = 0;
          tmp = nl + 1;
          if (*tmp == '\r')
            tmp++;
        }
      else
        {
          ssh_rl_write_string(rl, tmp, cr - tmp);
          if (*(cr + 1) == '\n')
            {
              ssh_rl_send_string(rl, (unsigned char *) "\r\n", 2);
              cr++;
            }
          else
            ssh_rl_send_string(rl, (unsigned char *) "\r", 1);
          rl->display_cursor = 0;
          tmp = cr + 1;
        }
    }
  ssh_rl_write_string(rl, tmp, rl->prompt_len);

  if (*line != NULL)
    {
      rl->line_alloc = strlen((char *) *line) + 1;
      rl->line = *line;
    }
  else
    {
      rl->line_alloc = 80;
      rl->line = ssh_xmalloc(rl->line_alloc);
      rl->line[0] = '\0';
    }

  rl->display_line = ssh_xmalloc(rl->line_alloc);
  rl->display_line[0] = '\0';
  rl->end = rl->cursor = strlen((char *) rl->line);

  lr = ssh_rl_loop(rl);
  rm = ssh_rl_restore_tty_modes(rl);

  if ((lr < 0) || (rm < 0))
    {
      for(i = 0; i < rl->undo_length; i++)
        ssh_xfree(rl->undo[i]);
      if (rl->yank != NULL)
        ssh_xfree(rl->yank);
      ssh_xfree(rl->undo);
      ssh_xfree(rl->undo_cursors);
      ssh_xfree(rl->line);
      ssh_xfree(rl);
      *line = NULL;
      return -1;
    }
  for(i = 0; i < rl->undo_length; i++)
    ssh_xfree(rl->undo[i]);
  if (rl->yank != NULL)
    ssh_xfree(rl->yank);
  ssh_xfree(rl->undo);
  ssh_xfree(rl->undo_cursors);
  *line = rl->line;             /* Line is not freed, it is returned */
  rl->line[rl->end] = '\0';
  ssh_xfree(rl);
  return strlen((char *) *line);
}
