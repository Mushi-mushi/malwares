/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshreadline
 *        $Source: /ssh/CVS/src/lib/sshreadline/sshreadline.h,v $
 *        $Author: tmo $
 *
 *        Creation          : 19:52 Mar 12 1997 kivinen
 *        Last Modification : 01:01 Mar 17 1997 kivinen
 *        Last check in     : $Date: 1999/03/17 08:51:59 $
 *        Revision number   : $Revision: 1.4 $
 *        State             : $State: Exp $
 *        Version           : 1.12
 *
 *        Description       : Readline library
 *
 *
 *        $Log: sshreadline.h,v $
 *        $EndLog$
 */

#ifndef SSHREADLINE_H
#define SSHREADLINE_H

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
                 int fd);


/*
 * Read line from user. The tty at file descriptor FD is put to raw
 * mode and data is read until CR is received. The PROMPT is used to prompt
 * the input. DEF is the initial data that is editable on the readline. .
 *
 * When the line has been read, the function will call provided CALLBACK
 * once providing it the data read and the file handle where the data was 
 * received. The data is available only during the callback execution.
 *
 * The ssh_readline_eloop will return zero in success , or -1 if there 
 * is some kind of initialization error.
 */
typedef void (*SshRLCallback)(int fd, const char *line);

int ssh_readline_eloop(const unsigned char *prompt,
                       const unsigned char *def,
                       int fd,
                       SshRLCallback callback);

#endif /* SSHREADLINE_H */
