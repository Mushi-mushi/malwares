/*
 * support.h	This file contains the definitions of what is in the
 *		support library.  Most of all, it defines structures
 *		for accessing support modules, and the function proto-
 *		types.
 *
 * Version:	@(#)support.h	1.10	10/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		Copyright 1993 MicroWalt Corporation
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */


/* This structure defines protocol families and their handlers. */
struct aftype {
  char		*name;
  char		*title;
  int		af;
  int		alen;
  char		*(*print)	(unsigned char *);
  char		*(*sprint)	(struct sockaddr *, int numeric);
  int		(*input)	(char *bufp, struct sockaddr *);
  void		(*herror)	(char *text);
};


/* This structure defines hardware protocols and their handlers. */
struct hwtype {
  char		*name;
  char		*title;
  int		type;
  int		alen;
  char		*(*print)	(unsigned char *);
  char		*(*sprint)	(struct sockaddr *);
  int		(*input)	(char *, struct sockaddr *);
  int		(*activate)	(int fd);
};


extern struct hwtype	*get_hwtype(char *name);
extern struct hwtype	*get_hwntype(int type);
extern struct aftype	*get_aftype(char *name);
extern struct aftype	*get_afntype(int type);

extern char		*getsock(char *bufp, struct sockaddr *sap);


/* End of support.h */
