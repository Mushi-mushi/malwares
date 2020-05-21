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
 *
 *	$Id: gshadow_.h,v 1.1.1.1 1996/08/10 07:59:51 marekm Exp $
 */

#ifndef	_H_GSHADOW
#define	_H_GSHADOW

/*
 * Shadow group security file structure
 */

struct	sgrp {
	char	*sg_name;	/* group name */
	char	*sg_passwd;	/* group password */
	char	**sg_adm;	/* group administator list */
	char	**sg_mem;	/* group membership list */
};

/*
 * Shadow group security file functions.
 */

#include <stdio.h>  /* for FILE */

#if __STDC__
struct	sgrp	*getsgent (void);
struct	sgrp	*getsgnam (const char *);
struct	sgrp	*sgetsgent (const char *);
struct	sgrp	*fgetsgent (FILE *);
void	setsgent (void);
void	endsgent (void);
int	putsgent (const struct sgrp *, FILE *);
#else
struct	sgrp	*getsgent ();
struct	sgrp	*getsgnam ();
struct	sgrp	*sgetsgent ();
struct	sgrp	*fgetsgent ();
void	setsgent ();
void	endsgent ();
int	putsgent ();
#endif

#define	GSHADOW	"/etc/gshadow"
#endif /* ifndef _H_GSHADOW */
