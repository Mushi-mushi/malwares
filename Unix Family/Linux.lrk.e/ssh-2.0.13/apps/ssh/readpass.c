/*

readpass.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Jul 10 22:08:59 1995 ylo

Functions for reading passphrases and passwords.

*/

#include "ssh2includes.h"
#include "readpass.h"

#define SSH_DEBUG_MODULE "SshReadPass"

/* Saved old terminal mode for read_passphrase. */
#ifdef USING_TERMIOS
static struct termios saved_tio;
#endif
#ifdef USING_SGTTY
static struct sgttyb saved_tio;
#endif

/* Old interrupt signal handler for read_passphrase. */
static RETSIGTYPE (*old_handler)(int sig) = NULL;

/* Interrupt signal handler for read_passphrase. */

RETSIGTYPE ssh_rp_intr_handler(int sig)
{
  /* Restore terminal modes. */
#ifdef USING_TERMIOS
  tcsetattr(fileno(stdin), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(stdin), TIOCSETP, &saved_tio);
#endif
  /* Restore the old signal handler. */
  signal(sig, old_handler);
  /* Resend the signal, with the old handler. */
  kill(getpid(), sig);
}

/* Reads a passphrase from /dev/tty with echo turned off.  Returns the 
   passphrase (allocated with ssh_xmalloc).  Returns NULL if EOF is encountered. 
   The passphrase if read from stdin if from_stdin is true (as is the
   case with ssh-keygen).  */

char *ssh_read_passphrase(const char *prompt, int from_stdin)
{
  char buf[1024], *cp;
  unsigned char quoted_prompt[512];
  unsigned const char *p;
#ifdef USING_TERMIOS
  struct termios tio;
#endif
#ifdef USING_SGTTY
  struct sgttyb tio;
#endif
  FILE *f;
  int i;
  
  if (from_stdin)
    f = stdin;
  else
    {
      /* Read the passphrase from /dev/tty to make it possible to ask it even 
         when stdin has been redirected. */
      f = fopen("/dev/tty", "r");
      if (!f)
        {
          if (getenv("DISPLAY"))
            {
              char command[512];
              
              fprintf(stderr,
                      "Executing ssh-askpass to query the password...\n");
              fflush(stdout);
              fflush(stderr);
              for(p = (unsigned const char *) prompt, i = 0;
                  i < sizeof(quoted_prompt) - 5 && *p;
                  i++, p++)
                {
                  if (*p == '\'')
                    {
                      quoted_prompt[i++] = '\'';
                      quoted_prompt[i++] = '\\';
                      quoted_prompt[i++] = '\'';
                      quoted_prompt[i] = '\'';
                    }
                  else if (isprint(*p) || isspace(*p))
                    quoted_prompt[i] = *p;
                  else if (iscntrl(*p))
                    {
                      quoted_prompt[i++] = '^';
                      if (*p < ' ')
                        quoted_prompt[i] = *p + '@';
                      else
                        quoted_prompt[i] = '?';
                    }
                  else if (*p > 128)
                    quoted_prompt[i] = *p;
                }
              quoted_prompt[i] = '\0';
  
              snprintf(command, sizeof(command),
                       "ssh-askpass '%.400s'", quoted_prompt);
              
              f = popen(command, "r");
              if (f == NULL)
                {
                  fprintf(stderr, "Could not query passphrase: '%.200s' failed.\n",
                          command);
                  return NULL;
                }
              if (!fgets(buf, sizeof(buf), f))
                {
                  pclose(f);
                  fprintf(stderr, "No passphrase supplied.\n");
                  return NULL;
                }
              pclose(f);
              if (strchr(buf, '\n'))
                *strchr(buf, '\n') = 0;
              return ssh_xstrdup(buf);
            }

          /* No controlling terminal and no DISPLAY.  Nowhere to read. */
          fprintf(stderr, "You have no controlling tty and no DISPLAY.  Cannot read passphrase.\n");
          return NULL;
        }
    }

  for(p = (unsigned const char *) prompt, i = 0;
      i < sizeof(quoted_prompt) - 4 && *p; i++, p++)
    {
      if (isprint(*p) || isspace(*p))
        quoted_prompt[i] = *p;
      else if (iscntrl(*p))
        {
          quoted_prompt[i++] = '^';
          if (*p < ' ')
            quoted_prompt[i] = *p + '@';
          else
            quoted_prompt[i] = '?';
        }
      else if (*p > 128)
        quoted_prompt[i] = *p;
    }
  quoted_prompt[i] = '\0';
  
  /* Display the prompt (on stderr because stdout might be redirected). */
  fflush(stdout);
  fprintf(stderr, "%s", quoted_prompt);
  fflush(stderr);

  /* Get terminal modes. */
#ifdef USING_TERMIOS
  tcgetattr(fileno(f), &tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(f), TIOCGETP, &tio);
#endif
  saved_tio = tio;
  /* Save signal handler and set the new handler. */
  old_handler = signal(SIGINT, ssh_rp_intr_handler);

  /* Set new terminal modes disabling all echo. */
#ifdef USING_TERMIOS
  tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fileno(f), TCSANOW, &tio);
#endif
#ifdef USING_SGTTY
  tio.sg_flags &= ~(ECHO);
  ioctl(fileno(f), TIOCSETP, &tio);
#endif

  /* Read the passphrase from the terminal. */
  if (fgets(buf, sizeof(buf), f) == NULL)
    {
      /* Got EOF.  Just return NULL. */
      /* Restore terminal modes. */
#ifdef USING_TERMIOS
      tcsetattr(fileno(f), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
      ioctl(fileno(f), TIOCSETP, &saved_tio);
#endif
      /* Restore the signal handler. */
      signal(SIGINT, old_handler);
      /* Print a newline (the prompt probably didn\'t have one). */
      fprintf(stderr, "\n");
      /* Close the file. */
      if (f != stdin)
        fclose(f);
      return NULL;
    }
  /* Restore terminal modes. */
#ifdef USING_TERMIOS
  tcsetattr(fileno(f), TCSANOW, &saved_tio);
#endif
#ifdef USING_SGTTY
  ioctl(fileno(f), TIOCSETP, &saved_tio);
#endif
  /* Restore the signal handler. */
  (void)signal(SIGINT, old_handler);
  /* Remove newline from the passphrase. */
  if (strchr(buf, '\n'))
    *strchr(buf, '\n') = 0;
  /* Allocate a copy of the passphrase. */
  cp = ssh_xstrdup(buf);
  /* Clear the buffer so we don\'t leave copies of the passphrase laying
     around. */
  memset(buf, 0, sizeof(buf));
  /* Print a newline since the prompt probably didn\'t have one. */
  fprintf(stderr, "\n");
  /* Close the file. */
  if (f != stdin)
    fclose(f);
  return cp;
}


/* Reads a yes/no confirmation from /dev/tty.  Returns TRUE if "yes" is
   received.  Otherwise returns FALSE (also if EOF is encountered). */

Boolean ssh_read_confirmation(const char *prompt)
{
  char buf[1024], *p;
  FILE *f;
  
  if (isatty(fileno(stdin)))
    f = stdin;
  else
    {
      /* Read the passphrase from /dev/tty to make it possible to ask it even 
         when stdin has been redirected. */
      f = fopen("/dev/tty", "r");
      if (!f)
        {
          fprintf(stderr, "You have no controlling tty.  Cannot read "
                  "confirmation.\n");
          return FALSE;
        }
    }

  /* Read the passphrase from the terminal. */
  do
    {
      /* Display the prompt (on stderr because stdout might be redirected). */
      fflush(stdout);
      fprintf(stderr, "%s", prompt);
      fflush(stderr);
      /* Read line */
      if (fgets(buf, sizeof(buf), f) == NULL)
        {
          /* Got EOF.  Just exit. */
          /* Print a newline (the prompt probably didn\'t have one). */
          fprintf(stderr, "\n");
          fprintf(stderr, "Aborted by user");
          /* Close the file. */
          if (f != stdin)
            fclose(f);
          return FALSE;
        }
      p = buf + strlen(buf) - 1;
      while (p > buf && isspace(*p))
        *p-- = '\0';
      p = buf;
      while (*p && isspace(*p))
        p++;
      if (strcmp(p, "no") == 0)
        {
          /* Close the file. */
          if (f != stdin)
            fclose(f);
          return FALSE;
        }
    } while (strcmp(p, "yes") != 0);
  /* Close the file. */
  if (f != stdin)
    fclose(f);
  return TRUE;
}
