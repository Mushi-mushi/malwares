/*
 * Copyright 1989 - 1994, John F. Haugh II
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

/*
 * Separated from setup.c.  --marekm
 * Resource limits thanks to Cristian Gafton.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: limits.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>

#include "prototypes.h"
#include "defines.h"
#include <pwd.h>
#include "getdef.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#define LIMITS
#endif

#ifdef LIMITS

#ifndef LIMITS_FILE
#define LIMITS_FILE "/etc/limits"
#endif

#define LOGIN_ERROR_RLIMIT	1
#define LOGIN_ERROR_LOGIN	2

/* Set a limit on a resource */
static int
setrlimit_value(rlimit, value, multiplier)
	unsigned int rlimit;	/* RLIMIT_XXXX */
	const char *value;	/* string value to be read */
	unsigned int multiplier; /* value*multiplier is the actual limit */
{
	struct rlimit rlim;
	long limit;
	char **endptr = (char **) &value;
	const char *value_orig = value;

	limit = strtol(value, endptr, 10);
	if (limit == 0 && value_orig == *endptr) /* no chars read */
		return 0;
	limit *= multiplier;
	rlim.rlim_cur = limit;
	rlim.rlim_max = limit;
	if (setrlimit(rlimit, &rlim))
		return LOGIN_ERROR_RLIMIT;
	return 0;
}

/* Counts the number of user logins and check against the limit*/
static int
check_logins(name, maxlogins)
	const char *name;
	const char *maxlogins;
{
	struct utmp *ut;
	unsigned int limit, count;
	char **endptr = (char **) &maxlogins;
	const char *ml_orig = maxlogins;

	limit = strtol(maxlogins, endptr, 10);
	if (limit == 0 && ml_orig == *endptr) /* no chars read */
		return 0;

	if (limit == 0) /* maximum 0 logins ? */ {
		SYSLOG((LOG_WARN, "No logins allowed for `%s'\n", name));
		return LOGIN_ERROR_LOGIN;
	}

	setutent();
	count = 0;
	while ((ut = getutent())) {
#ifdef USER_PROCESS
		if (ut->ut_type != USER_PROCESS)
			continue;
#endif
		if (ut->UT_USER[0] == '\0')
			continue;
		if (strncmp(name, ut->UT_USER, sizeof(ut->UT_USER)) != 0)
			continue;
		if (++count >= limit)
			break;
	}
	endutent();
	if (count >= limit) {
		SYSLOG((LOG_WARN, "Too many logins (max %d) for %s\n",
			limit, name));
		return LOGIN_ERROR_LOGIN;
	}
	return 0;
}

/* Function setup_user_limits - checks/set limits for the curent login
 * Original idea from Joel Katz's lshell. Ported to shadow-login
 * by Cristian Gafton - gafton@sorosis.ro
 *
 * We are passed a string of the form ('BASH' constants for ulimit)
 *     [Cc][Dd][Ff][Mm][Nn][Rr][Ss][Tt][Uu][Ll]
 *     (eg. 'C2F256D2048N5' or 'C2 F256 D2048 N5')
 * where:
 * [Cc]: c = RLIMIT_CORE	max core file size (KB)
 * [Dd]: d = RLIMIT_DATA	max data size (KB)
 * [Ff]: f = RLIMIT_FSIZE	Maximum filesize (KB)
 * [Mm]: m = RLIMIT_MEMLOCK	max locked-in-memory address space (KB)
 * [Nn]: n = RLIMIT_NOFILE	max number of open files
 * [Rr]: r = RLIMIT_RSS		max resident set size (KB)
 * [Ss]: s = RLIMIT_STACK	max stack size (KB)
 * [Tt]: t = RLIMIT_CPU		max CPU time (MIN)
 * [Uu]: u = RLIMIT_NPROC	max number of processes
 * [Ll]: l = max number of logins for this user
 *
 * Return value:
 *		0 = okay, of course
 *		LOGIN_ERROR_RLIMIT = error setting some RLIMIT
 *		LOGIN_ERROR_LOGIN  = error - too many logins for this user
 */
static int
do_user_limits(buf, name)
	const char *buf;	/* the limits string */
	const char *name;	/* the username */
{
	const char *pp;
	int retval = 0;

	pp=buf;

	while (*pp != '\0') switch(*pp++) {
#ifdef RLIMIT_CPU
		case 't':
		case 'T':
			/* RLIMIT_CPU - max CPU time (MIN) */
			retval |= setrlimit_value(RLIMIT_CPU, pp, 60);
			break;
#endif
#ifdef RLIMIT_DATA
		case 'd':
		case 'D':
			/* RLIMIT_DATA - max data size (KB) */
			retval |= setrlimit_value(RLIMIT_DATA, pp, 1024);
			break;
#endif
#ifdef RLIMIT_FSIZE
		case 'f':
		case 'F':
			/* RLIMIT_FSIZE - Maximum filesize (KB) */
			retval |= setrlimit_value(RLIMIT_FSIZE, pp, 1024);
			break;
#endif
#ifdef RLIMIT_NPROC
		case 'u':
		case 'U':
			/* RLIMIT_NPROC - max number of processes */
			retval |= setrlimit_value(RLIMIT_NPROC, pp, 1);
			break;
#endif
#ifdef RLIMIT_CORE
		case 'c':
		case 'C':
			/* RLIMIT_CORE - max core file size (KB) */
			retval |= setrlimit_value(RLIMIT_CORE, pp, 1024);
			break;
#endif
#ifdef RLIMIT_MEMLOCK
		case 'm':
		case 'M':
		/* RLIMIT_MEMLOCK - max locked-in-memory address space (KB) */
			retval |= setrlimit_value(RLIMIT_MEMLOCK, pp, 1024);
			break;
#endif
#ifdef RLIMIT_NOFILE
		case 'n':
		case 'N':
			/* RLIMIT_NOFILE - max number of open files */
			retval |= setrlimit_value(RLIMIT_NOFILE, pp, 1);
			break;
#endif
#ifdef RLIMIT_RSS
		case 'r':
		case 'R':
			/* RLIMIT_RSS - max resident set size (KB) */
			retval |= setrlimit_value(RLIMIT_RSS, pp, 1024);
			break;
#endif
#ifdef RLIMIT_STACK
		case 's':
		case 'S':
			/* RLIMIT_STACK - max stack size (KB) */
			retval |= setrlimit_value(RLIMIT_STACK, pp, 1024);
			break;
#endif
		case 'l':
		case 'L':
			/* LIMIT the number of concurent logins */
			retval |= check_logins(name, pp);
			break;
	}
	return retval;
}

static int
setup_user_limits(uname)
	char *uname;
{
	/* TODO: allow and use @group syntax --cristiang */
	FILE *fil;
	char buf[1024];
	char name[1024];
	char limits[1024];
	char deflimits[1024];
	char tempbuf[1024];

	/* init things */
	bzero(buf, sizeof(buf));
	bzero(name, sizeof(name));
	bzero(limits, sizeof(limits));
	bzero(deflimits, sizeof(deflimits));
	bzero(tempbuf, sizeof(tempbuf));

	/* start the checks */
	fil = fopen(LIMITS_FILE, "r");
	if (fil == NULL) {
#if 0  /* no limits file is ok, not everyone is a BOFH :-).  --marekm */
		SYSLOG((LOG_WARN, NO_LIMITS, uname, LIMITS_FILE));
#endif
		return 0;
	}
	/* The limits file have the following format:
	 * - '#' (comment) chars only as first chars on a line;
	 * - username must start on first column
	 * A better (smarter) checking should be done --cristiang */
	while (fgets(buf, 1024, fil) != NULL) {
		if (buf[0]=='#' || buf[0]=='\n')
			continue;
		bzero(tempbuf, sizeof(tempbuf));
		/* a valid line should have a username, then spaces,
		 * then limits
		 * we allow the format:
		 * username    L2  D2048  R4096
		 * where spaces={' ',\t}. Also, we reject invalid limits.
		 * Imposing a limit should be done with care, so a wrong
		 * entry means no care anyway :-). A '-' as a limits
		 * strings means no limits --cristiang */
		if (sscanf(buf, "%s%[CDFMNRSTULcdfmnrstul0-9 \t-]",
		    name, tempbuf) == 2)
			if (strcmp(name, uname) == 0) {
				strcpy(limits, tempbuf);
				break;
			} else if (strcmp(name, "*") == 0) {
				strcpy(deflimits, tempbuf);
			}
	}
	fclose(fil);
	if (limits[0] == '\0') {
		/* no user specific limits */
		if (deflimits[0] == '\0') /* no default limits */
			return 0;
		strcpy(limits, deflimits); /* use the default limits */
	}
	return do_user_limits(limits, uname);
}
#endif  /* LIMITS */

/*
 *	set the process nice, ulimit, and umask from the password file entry
 */

void
setup_limits(info)
	const struct passwd *info;
{
	char	*cp;
	int	i;
	long	l;

	/*
	 * See if the GECOS field contains values for NICE, UMASK or ULIMIT.
	 * If this feature is enabled in /etc/login.defs, we make those
	 * values the defaults for this login session.
	 */

	if ( getdef_bool("QUOTAS_ENAB") ) {
#ifdef LIMITS
		if (info->pw_uid)
		if (setup_user_limits(info->pw_name) & LOGIN_ERROR_LOGIN) {
			fprintf(stderr, "Too many logins.\n");
			sleep(2);
			exit(1);
		}
#endif
		for (cp = info->pw_gecos ; cp != NULL ; cp = strchr (cp, ',')) {
			if (*cp == ',')
				cp++;

			if (strncmp (cp, "pri=", 4) == 0) {
				i = atoi (cp + 4);
				if (i >= -20 && i <= 20)
					(void) nice (i);

				continue;
			}
			if (strncmp (cp, "ulimit=", 7) == 0) {
				l = strtol (cp + 7, (char **) 0, 10);
				set_filesize_limit(l);
				continue;
			}
			if (strncmp (cp, "umask=", 6) == 0) {
				i = strtol (cp + 6, (char **) 0, 8) & 0777;
				(void) umask (i);

				continue;
			}
		}
	}
}
