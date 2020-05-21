/*

sshmalloc.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 22:09:17 1995 ylo

Versions of malloc and friends that check their results, and never return
failure (they call fatal if they encounter an error).

*/

/*
 * $Id: sshmalloc.h,v 1.4 1999/04/20 23:47:05 kivinen Exp $
 * $Log: sshmalloc.h,v $
 * $EndLog$
 */

#ifndef XMALLOC_H
#define XMALLOC_H

/* This XMALLOC_MAX_SIZE is the maximum size that x*alloc routines can allocate
   with one call. */

#ifdef WINDOWS
#ifdef WIN32
#define XMALLOC_MAX_SIZE (100*1024L*1024L)
#else  /* WIN32 */
#define XMALLOC_MAX_SIZE 65500L
#endif  /* WIN32 */
#else  /* WINDOWS */
#define XMALLOC_MAX_SIZE (1024*1024L*1024L)
#endif /* WINDOWS */

#ifdef DEBUG_LIGHT
#define SSH_DEBUG_MALLOC
#endif /* DEBUG_LIGHT */

/* Like malloc, but calls ssh_fatal() if out of memory.  Allocating zero bytes
   is permitted, and results in a valid object. */
DLLEXPORT void *DLLCALLCONV
ssh_xmalloc(unsigned long size);

/* Like realloc, but calls ssh_fatal() if out of memory.  ptr may be NULL,
   in which case this behaves like ssh_xmalloc.  new_size may be zero, in which
   case a valid object is returned. */
DLLEXPORT void *DLLCALLCONV
ssh_xrealloc(void *ptr, unsigned long new_size);

/* Allocates a buffer of size nitems*size, and fills the buffer with
   zeroes.  It is guaranteed that allocating zero bytes works, and
   returns a valid object.  */
DLLEXPORT void *DLLCALLCONV
ssh_xcalloc(unsigned long nitems, unsigned long size);

/* Frees memory allocated using ssh_xmalloc or ssh_xrealloc. If ptr is NULL
   nothing is done. */
DLLEXPORT void DLLCALLCONV
ssh_xfree(void *ptr);

/* Allocates memory using ssh_xmalloc, and copies the string into that memory.
   This takes and returns void pointers so that this can also be used
   for unsigned char strings. */
DLLEXPORT void *DLLCALLCONV
ssh_xstrdup(const void *str);

/* Allocates memory using ssh_xmalloc, and copies the buffer into that memory.
   This takes and returns void pointers so that this can also be used
   for unsigned char strings. Note, that the string will always be null
   terminated.  The returned pointer is properly aligned for any type of
   data. */
DLLEXPORT void *DLLCALLCONV
ssh_xmemdup(const void *str, unsigned long len);

#endif /* XMALLOC_H */
