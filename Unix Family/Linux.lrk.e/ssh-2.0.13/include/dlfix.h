/*

  dlfix.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jul 21 17:40:10 1997 [mkojo]

  Discrete logarithm predefined groups.

  */

/*
 * $Id: dlfix.h,v 1.3 1999/04/29 13:37:53 huima Exp $
 * $Log: dlfix.h,v $
 * $EndLog$
 */

#ifndef DLFIX_H
#define DLFIX_H

/* Search a parameter set of name "name". Returns TRUE if found. */

Boolean ssh_dlp_set_param(const char *name, const char **outname,
                          SshInt *p, SshInt *q, SshInt *g);

#endif /* DLFIX_H */
