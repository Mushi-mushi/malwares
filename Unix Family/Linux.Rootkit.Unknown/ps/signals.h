/* signals.h - signal name handling */

void list_signals(void);

/* Lists all known signal names on standard output. */

int get_signal(char *name,char *cmd);

/* Returns the signal number of NAME. If no such signal exists, an error
   message is displayed and the program is terminated. CMD is the name of the
   application. */

int get_signal2(char *name);
/* Returns the signal number of NAME, which points to a numeric or
   symbolic string (e.g., "9" or "HUP").  Returns -1 on failure.
   By Michael Shields 1994/04/25 for top cleanup. */
