/*

  sshmath-types.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Apr 27 20:07:29 1998 [mkojo]

  Definitions for types and definitions that are often used in
  SSH arithmetic library components.

  */

/*
 * $Id: sshmath-types.h,v 1.5 1999/03/26 17:18:52 huima Exp $
 * $Log: sshmath-types.h,v $
 * $EndLog$
 */

#ifndef SSHMATH_TYPES_H
#define SSHMATH_TYPES_H

/* XXX One should build a way to define these things automagically.
   This is something that should be done in future. */

/* This is the current word used internally, however, one should build
   a better system later for deducing the fastest available word size. */

/* The definitions later _in this file_ assume currently that SshWord
   is the long integer. */
typedef unsigned long SshWord;
typedef long          SignedSshWord;

/* SIZEOF_LONG is defined typically in sshconf.h. */
#ifndef SIZEOF_LONG
#error SIZEOF_LONG is not defined! (see sshmath-types.h)
#endif

/* SSH_WORD_BITS cannot be defined as sizeof(SshWord) because
   `sizeof' cannot appear in a preprocessor conditional. */
#define SSH_WORD_BITS (SIZEOF_LONG * 8)
#define SSH_WORD_HALF_BITS (SSH_WORD_BITS / 2)
#define SSH_WORD_MASK (~(SshWord)0)

#endif /* SSHMATH_TYPES_H */

