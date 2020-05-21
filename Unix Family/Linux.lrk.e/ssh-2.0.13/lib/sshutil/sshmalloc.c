/*

sshmalloc.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:23:10 1995 ylo

Versions of malloc and friends that check their results, and never return
failure (they call fatal if they encounter an error).

*/

/*
 * $Id: sshmalloc.c,v 1.9 1999/04/30 07:05:25 tmo Exp $
 * $Log: sshmalloc.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#define SSH_DEBUG_MODULE "SshMalloc"

#ifdef malloc
# undef malloc
# undef calloc
# undef realloc
# undef free
# undef memdup
# undef strdup
#endif

#ifdef SSH_DEBUG_MALLOC
#include "sshgetput.h"
#define SSH_DEBUG_MALLOC_SIZE_BEFORE    8
#define SSH_DEBUG_MALLOC_SIZE_AFTER     4
#define SSH_DEBUG_MALLOC_MAGIC_IN_USE   0x21041999
#define SSH_DEBUG_MALLOC_MAGIC_FREED    0x13061968
#define SSH_DEBUG_MALLOC_MAGIC_AFTER    0x99190214
#endif /* SSH_DEBUG_MALLOC */

void *ssh_xmalloc(unsigned long size)
{
  void *ptr;

  if (size > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xmalloc: allocation too large (allocating %ld bytes)",
              size);

  if (size == 0)
    size = 1;
#ifdef SSH_DEBUG_MALLOC
  ptr = (void *)malloc((size_t) size + SSH_DEBUG_MALLOC_SIZE_BEFORE +
                       SSH_DEBUG_MALLOC_SIZE_AFTER);
  if (ptr == NULL)
    ssh_fatal("ssh_xmalloc: out of memory (allocating %ld bytes)", size);

  SSH_PUT_32BIT(ptr, size);
  SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
  SSH_PUT_32BIT((unsigned char *) ptr + size + SSH_DEBUG_MALLOC_SIZE_BEFORE,
                SSH_DEBUG_MALLOC_MAGIC_AFTER);
  ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#else /* SSH_DEBUG_MALLOC */
  ptr = (void *)malloc((size_t) size);
  if (ptr == NULL)
    ssh_fatal("ssh_xmalloc: out of memory (allocating %ld bytes)", size);
#endif /* SSH_DEBUG_MALLOC */
  return ptr;
}

void *ssh_xcalloc(unsigned long nitems, unsigned long size)
{
  void *ptr;
  
  if (nitems == 0)
    nitems = 1;
  if (size == 0)
    size = 1;

  if (size * nitems > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xcalloc: allocation too large (allocating %ld*%ld bytes)",
          size, nitems);

#ifdef SSH_DEBUG_MALLOC
  ptr = (void *)malloc(((size_t) nitems * (size_t) size) +
                       SSH_DEBUG_MALLOC_SIZE_BEFORE +
                       SSH_DEBUG_MALLOC_SIZE_AFTER);

  if (ptr == NULL)
    ssh_fatal("ssh_xcalloc: out of memory (allocating %ld*%ld bytes)",
          nitems, size);

  memset((unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE,
         0, (nitems * size));
  SSH_PUT_32BIT(ptr, (size * nitems));
  SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
  SSH_PUT_32BIT((unsigned char *) ptr + (size * nitems) +
                SSH_DEBUG_MALLOC_SIZE_BEFORE,
                SSH_DEBUG_MALLOC_MAGIC_AFTER);
  ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#else /* SSH_DEBUG_MALLOC */
  ptr = (void *)calloc((size_t) nitems, (size_t) size);
  
  if (ptr == NULL)
    ssh_fatal("ssh_xcalloc: out of memory (allocating %ld*%ld bytes)",
          nitems, size);
#endif /* SSH_DEBUG_MALLOC */
  return ptr;
}

void *ssh_xrealloc(void *ptr, unsigned long new_size)
{
  void *new_ptr;

  if (ptr == NULL)
    return ssh_xmalloc(new_size);

  if (new_size > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xrealloc: allocation too large (allocating %ld bytes)",
              (long)new_size);
  
  if (new_size == 0)
    new_size = 1;
#ifdef SSH_DEBUG_MALLOC
  if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
      SSH_DEBUG_MALLOC_MAGIC_IN_USE)
    {
      if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
          SSH_DEBUG_MALLOC_MAGIC_FREED)
        ssh_fatal("Reallocating block that is already freed");
      ssh_fatal("Reallocating block that is either not mallocated, or whose magic number before the object was overwritten");
    }
  else
    {
      unsigned long old_size;

      old_size = SSH_GET_32BIT((unsigned char *) ptr -
                               SSH_DEBUG_MALLOC_SIZE_BEFORE);
      if (SSH_GET_32BIT((unsigned char *) ptr + old_size) !=
          SSH_DEBUG_MALLOC_MAGIC_AFTER)
        ssh_fatal("Reallocating block whose magic number after the object was overwritten");

      /* Mark the old block freed */
      SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
      SSH_PUT_32BIT((unsigned char *) ptr + old_size,
                    SSH_DEBUG_MALLOC_MAGIC_FREED);

      new_ptr = (void *)realloc((unsigned char *) ptr -
                                SSH_DEBUG_MALLOC_SIZE_BEFORE,
                                (size_t) new_size +
                                SSH_DEBUG_MALLOC_SIZE_BEFORE +
                                SSH_DEBUG_MALLOC_SIZE_AFTER);
      if (new_ptr == NULL)
        ssh_fatal("ssh_xrealloc: out of memory (new_size %ld bytes)",
                  (long)new_size);

      SSH_PUT_32BIT(new_ptr, new_size);
      SSH_PUT_32BIT((unsigned char *) new_ptr + 4,
                    SSH_DEBUG_MALLOC_MAGIC_IN_USE);
      SSH_PUT_32BIT((unsigned char *) new_ptr + new_size +
                    SSH_DEBUG_MALLOC_SIZE_BEFORE,
                    SSH_DEBUG_MALLOC_MAGIC_AFTER);
      new_ptr = (unsigned char *) new_ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
    }
#else /* SSH_DEBUG_MALLOC */
  new_ptr = (void *)realloc(ptr, (size_t) new_size);
  if (new_ptr == NULL)
    ssh_fatal("ssh_xrealloc: out of memory (new_size %ld bytes)",
              (long)new_size);
#endif /* SSH_DEBUG_MALLOC */
  return new_ptr;
}

void ssh_xfree(void *ptr)
{
#ifdef SSH_DEBUG_MALLOC
  if (ptr != NULL)
    {
      unsigned long size;

      if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
          SSH_DEBUG_MALLOC_MAGIC_IN_USE)
        {
          if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
              SSH_DEBUG_MALLOC_MAGIC_FREED)
            ssh_fatal("Freeing block that is already freed");
          ssh_fatal("Freeing block that is either not mallocated, or whose magic number before the object was overwritten");
        }

      size = SSH_GET_32BIT((unsigned char *) ptr -
                           SSH_DEBUG_MALLOC_SIZE_BEFORE);
      if (SSH_GET_32BIT((unsigned char *) ptr + size) !=
          SSH_DEBUG_MALLOC_MAGIC_AFTER)
        ssh_fatal("Freeing block whose magic number after the object was overwritten");

      /* Mark the old block freed */
      SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
      SSH_PUT_32BIT((unsigned char *) ptr + size,
                    SSH_DEBUG_MALLOC_MAGIC_FREED);
      free((unsigned char *) ptr - SSH_DEBUG_MALLOC_SIZE_BEFORE);
    }
#else /* SSH_DEBUG_MALLOC */
  if (ptr != NULL)
    free(ptr);
#endif /* SSH_DEBUG_MALLOC */
}

void *ssh_xstrdup(const void *p)
{
  const char *str;
  char *cp;

  SSH_ASSERT(p != NULL);
  str = (const char *)p;
  cp = ssh_xmalloc(strlen(str) + 1);
  strcpy(cp, str);
  return (void *)cp;
}

void *ssh_xmemdup(const void *p, unsigned long len)
{
  const char *str = (const char *)p;
  char *cp;
  
  if (len > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xmemdup: allocation too large (allocating %ld bytes)", len);
  
  cp = ssh_xmalloc(len + 1);
  memcpy(cp, str, (size_t)len);
  cp[len] = '\0';
  return (void *)cp;
}
