/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)rcmd.c	5.20 (Berkeley) 1/24/89";
#endif /* LIBC_SCCS and not lint */

#define const	/* XXX */

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <netdb.h>
#include <errno.h>
#include <setjmp.h>
#include <limits.h>
#ifdef NOPLUS
#include <syslog.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sys_defs.h"

#ifdef USE_SETRESXID
#define seteuid(a)	setresuid(-1,a,-1)
#define setegid(a)	setresgid(-1,a,-1)
#endif

#define bcopy(s,d,l) memcpy(d,s,l)
#define index	strchr

extern	errno;

/* BSD gid_t is short but {get,set}groups() want an array of integers */
#ifdef INT_GROUPS
#define GID_T	int
#else
#define GID_T	gid_t
#endif

#ifdef NO_NGROUPS_MAX
# define NGROUPS_MAX  NGROUPS
#endif

#if 0	/* XXX prototype problems */

rcmd(ahost, rport, locuser, remuser, cmd, fd2p)
	char **ahost;
	u_short rport;
	char *locuser, *remuser, *cmd;
	int *fd2p;
{
	int s, timo = 1, pid;
	sigset_t mask, oldmask;
	struct sockaddr_in sin, sin2, from;
	char c;
	int lport = IPPORT_RESERVED - 1;
	struct hostent *hp;
	fd_set reads;

	pid = getpid();
	hp = gethostbyname(*ahost);
	if (hp == 0) {
		fprintf(stderr, "%s: unknown host\n", *ahost);
		return (-1);
	}
	*ahost = hp->h_name;
	sigemptyset(&mask);
	sigaddset(&mask, SIGURG);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	for (;;) {
		s = rresvport(&lport);
		if (s < 0) {
			if (errno == EAGAIN)
				fprintf(stderr, "socket: All ports in use\n");
			else
				perror("rcmd: socket");
			sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *) 0);
			return (-1);
		}
		fcntl(s, F_SETOWN, pid);
		sin.sin_family = hp->h_addrtype;
		bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr, hp->h_length);
		sin.sin_port = rport;
		if (connect(s, (struct sockaddr *) &sin, sizeof (sin)) >= 0)
			break;
		(void) close(s);
		if (errno == EADDRINUSE) {
			lport--;
			continue;
		}
		if (errno == ECONNREFUSED && timo <= 16) {
			sleep(timo);
			timo *= 2;
			continue;
		}
		if (hp->h_addr_list[1] != NULL) {
			int oerrno = errno;

			fprintf(stderr,
			    "connect to address %s: ", inet_ntoa(sin.sin_addr));
			errno = oerrno;
			perror(0);
			hp->h_addr_list++;
			bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr,
			    hp->h_length);
			fprintf(stderr, "Trying %s...\n",
				inet_ntoa(sin.sin_addr));
			continue;
		}
		perror(hp->h_name);
		sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *) 0);
		return (-1);
	}
	lport--;
	if (fd2p == 0) {
		write(s, "", 1);
		lport = 0;
	} else {
		char num[8];
		int s2 = rresvport(&lport), s3;
		int len = sizeof (from);

		if (s2 < 0)
			goto bad;
		listen(s2, 1);
		(void) sprintf(num, "%d", lport);
		if (write(s, num, strlen(num)+1) != strlen(num)+1) {
			perror("write: setting up stderr");
			(void) close(s2);
			goto bad;
		}
		FD_ZERO(&reads);
		FD_SET(s, &reads);
		FD_SET(s2, &reads);
		errno = 0;
		if (select(32, &reads, 0, 0, 0) < 1 ||
		    !FD_ISSET(s2, &reads)) {
			if (errno != 0)
				perror("select: setting up stderr");
			else
			    fprintf(stderr,
				"select: protocol failure in circuit setup.\n");
			(void) close(s2);
			goto bad;
		}
		s3 = accept(s2, (struct sockaddr *) &from, &len);
		(void) close(s2);
		if (s3 < 0) {
			perror("accept");
			lport = 0;
			goto bad;
		}
		*fd2p = s3;
		from.sin_port = ntohs((u_short)from.sin_port);
		if (from.sin_family != AF_INET ||
		    from.sin_port >= IPPORT_RESERVED ||
		    from.sin_port < IPPORT_RESERVED / 2) {
			fprintf(stderr,
			    "socket: protocol failure in circuit setup.\n");
			goto bad2;
		}
	}
	(void) write(s, locuser, strlen(locuser)+1);
	(void) write(s, remuser, strlen(remuser)+1);
	(void) write(s, cmd, strlen(cmd)+1);
	if (read(s, &c, 1) != 1) {
		perror(*ahost);
		goto bad2;
	}
	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void) write(2, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad2;
	}
	sigsetmask(oldmask);
	return (s);
bad2:
	if (lport)
		(void) close(*fd2p);
bad:
	(void) close(s);
	sigsetmask(oldmask);
	return (-1);
}

#endif

rresvport(alport)
	int *alport;
{
	struct sockaddr_in sin;
	int s;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return (-1);
	for (;;) {
		sin.sin_port = htons((u_short)*alport);
		if (bind(s, (struct sockaddr *) &sin, sizeof (sin)) >= 0)
			return (s);
		if (errno != EADDRINUSE) {
			(void) close(s);
			return (-1);
		}
		(*alport)--;
		if (*alport == IPPORT_RESERVED/2) {
			(void) close(s);
			errno = EAGAIN;		/* close */
			return (-1);
		}
	}
}

int	_check_rhosts_file = 1;
static int _checkhost(), _checkuser();
#ifdef NIS
static char *nisdomain = 0;
#endif
static char *authf = 0;	/* hosts.equiv or rhosts */

ruserok(rhost, superuser, ruser, luser)
	char *rhost;
	int superuser;
	char *ruser, *luser;
{
	FILE *hostf;
	char fhost[MAXHOSTNAMELEN];
	register char *sp, *p;
	int baselen = -1;

#ifdef NIS
	if (nisdomain == 0)
		yp_get_default_domain(&nisdomain);
#endif

	sp = rhost;
	p = fhost;
	while (*sp) {
		if (*sp == '.') {
			if (baselen == -1)
				baselen = sp - rhost;
			*p++ = *sp++;
		} else {
			*p++ = isupper(*sp) ? tolower(*sp++) : *sp++;
		}
	}
	*p = '\0';

	/* If not superuser, process /etc/hosts.equiv file. */
	if (!superuser && (hostf = fopen(authf="/etc/hosts.equiv", "r")) != 0) {
		if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
			(void) fclose(hostf);
			return(0);
		}
		(void) fclose(hostf);
	}

	/* Process ~/.rhosts file as the user, in case it is remote. */
	if (_check_rhosts_file || superuser) {
		struct stat sbuf;
		struct passwd *pwd;
		char pbuf[MAXPATHLEN];
		uid_t saved_euid = geteuid();
		gid_t saved_egid = getegid();
		GID_T saved_groups[NGROUPS_MAX];
		int result;

#define restore_and_return(r) { result = (r); goto restore; }

		getgroups(NGROUPS_MAX, saved_groups);
		if ((pwd = getpwnam(luser)) == NULL)
			return(-1);

		(void) setegid(pwd->pw_gid);
		initgroups(pwd->pw_name, pwd->pw_gid);
		(void) seteuid(pwd->pw_uid);

		(void)strcpy(pbuf, pwd->pw_dir);
		(void)strcat(pbuf, "/.rhosts");
		if ((hostf = fopen(authf=pbuf, "r")) == NULL)
			restore_and_return(-1);
		/*
		 * if owned by someone other than user or root or if
		 * writeable by anyone but the owner, quit
		 */
		if (fstat(fileno(hostf), &sbuf) != 0) {
			syslog(LOG_ERR, "fstat(%s): %m", pbuf);
			fclose(hostf);
			restore_and_return(-1);
		}
		if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid) {
			fclose(hostf);
			syslog(LOG_ALERT, "%s: illegal owner uid %d",
				pbuf, sbuf.st_uid);
			restore_and_return(-1);
		}
		if (sbuf.st_mode & 022) {
			fclose(hostf);
			syslog(LOG_ALERT, "%s: illegal permission %3o",
				pbuf, sbuf.st_mode & 0777);
			restore_and_return(-1);
		}
		if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
			(void) fclose(hostf);
			restore_and_return(0);
		}
		(void) fclose(hostf);
		restore_and_return(-1);
restore:
		(void) setegid(saved_egid);
		(void) seteuid(saved_euid);
		setgroups(NGROUPS_MAX, saved_groups);
		return(result);
	}
	return (-1);
}

static jmp_buf abort_search;

/* don't make static, used by lpd(8) */
_validuser(hostf, rhost, luser, ruser, baselen)
	char *rhost, *luser, *ruser;
	FILE *hostf;
	int baselen;
{
	char *user;
	char ahost[MAXHOSTNAMELEN];
	register char *p;

	if (setjmp(abort_search) != 0)
		return (-1);

	while (fgets(ahost, sizeof (ahost), hostf)) {
		p = ahost;
		while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
			*p = isupper(*p) ? tolower(*p) : *p;
			p++;
		}
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (*p == ' ' || *p == '\t')
				p++;
			user = p;
			while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0')
				p++;
		} else
			user = p;
		*p = '\0';
		if (_checkhost(rhost, ahost, baselen) &&
		    _checkuser(ruser, user, luser)) {
			return (0);
		}
	}
	return (-1);
}

static
_checkhost(rhost, lhost, len)
	char *rhost, *lhost;
	int len;
{
	static char ldomain[MAXHOSTNAMELEN + 1];
	static char *domainp = NULL;
	static int nodomain = 0;
	register char *cp;

	if (lhost[0] == '+' && lhost[1] == 0)
#ifdef NOPLUS
	{
		syslog(LOG_ALERT, "wildcard in %s", authf);
		return(0);
	}
#else
		return(1);
#endif
#ifdef NIS
	if (lhost[0] == '+' && lhost[1] == '@')
		return(innetgr(lhost + 2, rhost, (char *) 0, nisdomain));
	if (lhost[0] == '-' && lhost[1] == '@') {
		if (innetgr(lhost + 2, rhost, (char *) 0, nisdomain))
			longjmp(abort_search, 1);
		return(0);
	}
#endif
	if (lhost[0] == '-') {
		if (_checkhost(rhost, lhost + 1, len))
			longjmp(abort_search, 1);
		return(0);
	}
	if (len == -1)
		return(!strcmp(rhost, lhost));
	if (strncmp(rhost, lhost, len))
		return(0);
	if (!strcmp(rhost, lhost))
		return(1);
	if (*(lhost + len) != '\0')
		return(0);
	if (nodomain)
		return(0);
	if (!domainp) {
		if (gethostname(ldomain, sizeof(ldomain)) == -1) {
			nodomain = 1;
			return(0);
		}
		ldomain[MAXHOSTNAMELEN] = 0;
		if ((domainp = index(ldomain, '.')) == (char *)NULL) {
			nodomain = 1;
			return(0);
		}
		for (cp = ++domainp; *cp; ++cp)
			if (isupper(*cp))
				*cp = tolower(*cp);
	}
	return(!strcmp(domainp, rhost + len +1));
}

static
_checkuser(ruser, user, luser)
	char *ruser, *user, *luser;
{
	if (user[0] == 0) {
		return(!strcmp(ruser, luser));
	} else {
		if (user[0] == '+' && user[1] == 0)
#ifdef NOPLUS
		{
			syslog(LOG_ALERT, "wildcard in %s", authf);
			return(0);
		}
#else
			return(1);
#endif
#ifdef NIS
		if (user[0] == '+' && user[1] == '@')
			return(innetgr(user + 2, (char *) 0, ruser, nisdomain));
		if (user[0] == '-' && user[1] == '@') {
			if (innetgr(user + 2, (char *) 0, ruser, nisdomain))
				longjmp(abort_search, 1);
			return(0);
		}
#endif
		if (user[0] == '-') {
			if (_checkuser(ruser, user + 1, luser))
				longjmp(abort_search, 1);
			return(0);
		}
		return(!strcmp(user, ruser));
	}
}
