/*

sshgetput.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

*/

#include "sshincludes.h"

#if defined(__i386__) && defined(__GNUC__)

/* Intel i386 processor, using AT&T syntax for gcc compiler. */

/* Lsb first cases could be done efficiently also with just C-definitions
   to just copy values. */
     
SshUInt32  SSH_GET_32BIT_LSB_FIRST(const unsigned char *cp)
{
  SshUInt32 result;
  __asm__("movl (%1), %0" : "=&r" (result) : "r" (cp));
  return result;
}

SshUInt16 SSH_GET_16BIT_LSB_FIRST(const unsigned char *cp)
{
  SshUInt16 result;
  __asm__("movw (%1), %0;" : "=&r" (result) : "r" (cp));
  return result;
}

void SSH_PUT_32BIT_LSB_FIRST(unsigned char *cp, SshUInt32 value)
{
  __asm__("movl %1, (%0)" : : "r" (cp), "r" (value));
}

void SSH_PUT_16BIT_LSB_FIRST(unsigned char *cp, SshUInt16 value)
{
  __asm__("movw %1, (%0)" : : "r" (cp), "r" (value));
}

/* Getting bytes msb first */

SshUInt32 SSH_GET_32BIT(const unsigned char *cp)
{ 
  SshUInt32 result;
  __asm__ volatile ("movl (%1), %0; rolw $8, %0; roll $16, %0; rolw $8, %0;"
          : "=&r" (result)
          : "r" (cp));
  return result;
}

SshUInt16 SSH_GET_16BIT(const unsigned char *cp)
{
  SshUInt16 result;
  __asm__ volatile ("movw (%1), %0; rolw $8, %0;"
          : "=&r" (result)
          : "r" (cp));
  return result;
}

/* Kludge. We must ensure that the value isn't reversed and thus need the ecx
   as a temporary variable! */ 
void SSH_PUT_32BIT(unsigned char *cp, SshUInt32 value)
{
  __asm__ volatile ("movl %1, %%ecx; rolw $8, %%cx; roll $16, %%ecx; rolw $8, %%cx;"
           "movl %%ecx, (%0);"
           : : "S" (cp), "a" (value) : "%ecx");
}

void SSH_PUT_16BIT(unsigned char *cp, SshUInt16 value)
{
  __asm__ volatile ("movw %1, %%cx; rolw $8, %%cx; movw %%cx, (%0);"
          : : "S" (cp), "a" (value) : "%cx");
}

#else

SshUInt32  SSH_GET_32BIT_LSB_FIRST(const unsigned char *cp)
{
  return  (((unsigned long)(unsigned char)(cp)[0]) |
           (((unsigned long)(unsigned char)(cp)[1]) << 8) | 
           (((unsigned long)(unsigned char)(cp)[2]) << 16) | 
           (((unsigned long)(unsigned char)(cp)[3]) << 24));
}

SshUInt16 SSH_GET_16BIT_LSB_FIRST(const unsigned char *cp)
{
  return (((unsigned long)(unsigned char)(cp)[0]) |
          (((unsigned long)(unsigned char)(cp)[1]) << 8));
}

void SSH_PUT_32BIT_LSB_FIRST(unsigned char *cp, SshUInt32 value)
{
  (cp)[0] = (unsigned char)(value); 
  (cp)[1] = (unsigned char)((value) >> 8); 
  (cp)[2] = (unsigned char)((value) >> 16); 
  (cp)[3] = (unsigned char)((value) >> 24); 
}

void SSH_PUT_16BIT_LSB_FIRST(unsigned char *cp, SshUInt16 value)
{
  (cp)[0] = (unsigned char)(value); 
  (cp)[1] = (unsigned char)((value) >> 8);
}

/* Getting bytes msb first */

SshUInt32 SSH_GET_32BIT(const unsigned char *cp)
{ 
  return ((((unsigned long)(unsigned char)(cp)[0]) << 24) | 
          (((unsigned long)(unsigned char)(cp)[1]) << 16) | 
          (((unsigned long)(unsigned char)(cp)[2]) << 8) | 
          ((unsigned long)(unsigned char)(cp)[3]));
}

SshUInt16 SSH_GET_16BIT(const unsigned char *cp)
{
  return ((((unsigned long)(unsigned char)(cp)[0]) << 8) | 
          ((unsigned long)(unsigned char)(cp)[1]));
}

void SSH_PUT_32BIT(unsigned char *cp, SshUInt32 value)
{
  (cp)[0] = (unsigned char)((value) >> 24); 
  (cp)[1] = (unsigned char)((value) >> 16); 
  (cp)[2] = (unsigned char)((value) >> 8); 
  (cp)[3] = (unsigned char)(value); 
}

void SSH_PUT_16BIT(unsigned char *cp, SshUInt16 value)
{
  (cp)[0] = (unsigned char)((value) >> 8);
  (cp)[1] = (unsigned char)(value); 
}
/*------------ macros for storing/extracting lsb first words -------------*/

     
#endif /* __i386__ */

