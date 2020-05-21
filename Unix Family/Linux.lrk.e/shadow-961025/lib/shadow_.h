/*
 * Copyright 1988 - 1994, John F. Haugh II
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

#ifndef	_H_SHADOW
#define	_H_SHADOW

/*
 * This information is not derived from AT&T licensed sources.  Posted
 * to the USENET 11/88, and updated 11/90 with information from SVR4.
 *
 *	$Id: shadow_.h,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $
 */

#ifdef	ITI_AGING
typedef	time_t	sptime;
#else
typedef	long	sptime;
#endif

/*
 * Shadow password security file structure.
 */

struct	spwd {
	char	*sp_namp;	/* login name */
	char	*sp_pwdp;	/* encrypted password */
	sptime	sp_lstchg;	/* date of last change */
	sptime	sp_min;		/* minimum number of days between changes */
	sptime	sp_max;		/* maximum number of days between changes */
	sptime	sp_warn;	/* number of days of warning before password
				   expires */
	sptime	sp_inact;	/* number of days after password expires
				   until the account becomes unusable. */
	sptime	sp_expire;	/* days since 1/1/70 until account expires */
	unsigned long	sp_flag; /* reserved for future use */
};

/*
 * Shadow password security file functions.
 */

#include <stdio.h>  /* for FILE */

#if defined(__STDC__)
struct	spwd	*getspent (void);
struct	spwd	*getspnam (const char *);
struct	spwd	*sgetspent (const char *);
struct	spwd	*fgetspent (FILE *);
void	setspent (void);
void	endspent (void);
int	putspent (const struct spwd *, FILE *);
#else
struct	spwd	*getspent ();
struct	spwd	*getspnam ();
struct	spwd	*sgetspent ();
struct	spwd	*fgetspent ();
void	setspent ();
void	endspent ();
int	putspent ();
#endif

#define  SHADOW "/etc/shadow"
#endif
