/*

Genrand.c

Author: Antti Huima <huima@ssh.fi>

Copyright (C) 1996 SSH Security Communications Oy, Espoo, Finland
                   All rights reserved
                 
*/

/*
 * $Id: genrand.c,v 1.14 1999/05/04 02:19:44 kivinen Exp $
 * $Log: genrand.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshgetput.h"
#include "md5.h"

/* Records. These are all internal to gencrypt. */

/* Definitions for random state */

#define SSH_RANDOM_STATE_BITS 8192
#define SSH_RANDOM_STATE_BYTES (SSH_RANDOM_STATE_BITS / 8)

/* SshRandomStateRec represents a generic random state structure. */

struct SshRandomStateRec {
  unsigned char state[SSH_RANDOM_STATE_BYTES];
  unsigned char stir_key[64];
  size_t next_available_byte;
  size_t add_position;
};

/* Cryptographically strong random number functions */

void ssh_random_xor_noise(SshRandomState state, size_t i,
                          SshUInt32 value)
{
  if (4 * i >= SSH_RANDOM_STATE_BYTES)
    ssh_fatal("ssh_random_xor_noise: internal error.");
  value ^= SSH_GET_32BIT(state->state + 4 * i);
  SSH_PUT_32BIT(state->state + 4 * i, value);
}

void ssh_random_acquire_light_environmental_noise(SshRandomState state)
{
  int f;
  unsigned char buf[32];
  int len;

#if !defined(WINDOWS) && !defined(DOS) && !defined(macintosh)
  /* If /dev/random is available, read some data from there in non-blocking
     mode and mix it into the pool. */
  f = open("/dev/random", O_RDONLY);
  if (f >= 0)
    {
      /* Set the descriptor into non-blocking mode. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
      fcntl(f, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
      fcntl(f, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
      len = read(f, buf, sizeof(buf));
      close(f);
      if (len > 0)
        ssh_random_add_noise(state, buf, len);
    }
#endif /* WINDOWS, DOS */

  /* Get miscellaneous noise from various system parameters and statistics. */
  ssh_random_xor_noise(state,
                       (size_t)(state->state[0] + 256*state->state[1]) % 
                       (SSH_RANDOM_STATE_BYTES / 4),
                       (SshUInt32)ssh_time());
#ifdef HAVE_CLOCK
    ssh_random_xor_noise(state, 3, (SshUInt32)clock());
#endif /* HAVE_CLOCK */
#ifdef HAVE_GETTIMEOFDAY
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ssh_random_xor_noise(state, 0, (SshUInt32)tv.tv_usec);
    ssh_random_xor_noise(state, 1, (SshUInt32)tv.tv_sec);
 }
#endif /* HAVE_GETTIMEOFDAY */
#ifdef HAVE_TIMES
  {
    struct tms tm;
    ssh_random_xor_noise(state, 2, (SshUInt32)times(&tm));
    ssh_random_xor_noise(state, 4, (SshUInt32)(tm.tms_utime ^
                                            (tm.tms_stime << 8) ^ 
                                            (tm.tms_cutime << 16) ^ 
                                            (tm.tms_cstime << 24)));
  }
#endif /* HAVE_TIMES */
#ifdef HAVE_GETRUSAGE
  {
    struct rusage ru, cru;
    getrusage(RUSAGE_SELF, &ru);
    getrusage(RUSAGE_CHILDREN, &cru);
    ssh_random_xor_noise(state, 0, (SshUInt32)(ru.ru_utime.tv_usec + 
                                            cru.ru_utime.tv_usec));
    ssh_random_xor_noise(state, 2, (SshUInt32)(ru.ru_stime.tv_usec + 
                                            cru.ru_stime.tv_usec));
    ssh_random_xor_noise(state, 5, (SshUInt32)(ru.ru_maxrss + cru.ru_maxrss));
    ssh_random_xor_noise(state, 6, (SshUInt32)(ru.ru_ixrss + cru.ru_ixrss));
    ssh_random_xor_noise(state, 7, (SshUInt32)(ru.ru_idrss + cru.ru_idrss));
    ssh_random_xor_noise(state, 8, (SshUInt32)(ru.ru_minflt + cru.ru_minflt));
    ssh_random_xor_noise(state, 9, (SshUInt32)(ru.ru_majflt + cru.ru_majflt));
    ssh_random_xor_noise(state, 10, (SshUInt32)(ru.ru_nswap + cru.ru_nswap));
    ssh_random_xor_noise(state, 11, (SshUInt32)(ru.ru_inblock + cru.ru_inblock));
    ssh_random_xor_noise(state, 12, (SshUInt32)(ru.ru_oublock + cru.ru_oublock));
    ssh_random_xor_noise(state, 13, (SshUInt32)((ru.ru_msgsnd ^ ru.ru_msgrcv ^ 
                                          ru.ru_nsignals) +
                                         (cru.ru_msgsnd ^ cru.ru_msgrcv ^ 
                                          cru.ru_nsignals)));
    ssh_random_xor_noise(state, 14, (SshUInt32)(ru.ru_nvcsw + cru.ru_nvcsw));
    ssh_random_xor_noise(state, 15, (SshUInt32)(ru.ru_nivcsw + cru.ru_nivcsw));
  }
#endif /* HAVE_GETRUSAGE */
#if !defined(WINDOWS) && !defined(DOS)
#ifdef HAVE_GETPID
  ssh_random_xor_noise(state, 11, (SshUInt32)getpid());
#endif /* HAVE_GETPID */
#ifdef HAVE_GETPPID
  ssh_random_xor_noise(state, 12, (SshUInt32)getppid());
#endif /* HAVE_GETPPID */
#ifdef HAVE_GETUID
  ssh_random_xor_noise(state, 10, (SshUInt32)getuid());
#endif /* HAVE_GETUID */
#ifdef HAVE_GETGID
  ssh_random_xor_noise(state, 10, (SshUInt32)(getgid() << 16));
#endif /* HAVE_GETGID */
#ifdef HAVE_GETPGRP
  ssh_random_xor_noise(state, 10, (SshUInt32)getpgrp());
#endif /* HAVE_GETPGRP */
#endif /* WINDOWS */
#ifdef _POSIX_CHILD_MAX
  ssh_random_xor_noise(state, 13, (SshUInt32)(_POSIX_CHILD_MAX << 16));
#endif /* _POSIX_CHILD_MAX */
#if defined(CLK_TCK) && !defined(WINDOWS) && !defined(DOS)
  ssh_random_xor_noise(state, 14, (SshUInt32)(CLK_TCK << 16));
#endif /* CLK_TCK && !WINDOWS */
}

DLLEXPORT SshRandomState DLLCALLCONV
ssh_random_allocate(void)
{
  size_t ctx_len;
  SshRandomState created;

  ctx_len = sizeof(*created);
  created = ssh_xmalloc(ctx_len);
  /* This isn't stricly necessary, but will keep programs like 3rd degree or
     purify silent. */
  memset(created, 0, ctx_len); 

  created->add_position = 0;
  created->next_available_byte = sizeof(created->stir_key);

  ssh_random_stir(created);
  
  return created;
}

/* Mixes the bytes from the buffer into the pool.  The pool should be stirred
   after a sufficient amount of noise has been added. */

DLLEXPORT void DLLCALLCONV
ssh_random_add_noise(SshRandomState state, const void *buf,
                     size_t bytes)
{
  size_t pos = state->add_position;
  const unsigned char *input = buf;
  while (bytes > 0)
    {
      if (pos >= SSH_RANDOM_STATE_BYTES)
        {
          pos = 0;
          ssh_random_stir(state);
        }
      state->state[pos] ^= *input;
      input++;
      bytes--;
      pos++;
    }
  state->add_position = pos;
}

/* Stirs the pool of randomness, making every bit of the internal state
   depend on every other bit.  This should be called after adding new
   randomness.  The stirring operation is irreversible, and a few bits of
   new randomness are automatically added before every stirring operation
   to make it even more impossible to reverse. */

DLLEXPORT void DLLCALLCONV
ssh_random_stir(SshRandomState state)
{
  SshUInt32 iv[4];
  size_t i;

  ssh_random_acquire_light_environmental_noise(state);

  /* Get IV from the beginning of the pool. */
  iv[0] = SSH_GET_32BIT(state->state + 0);
  iv[1] = SSH_GET_32BIT(state->state + 4);
  iv[2] = SSH_GET_32BIT(state->state + 8);
  iv[3] = SSH_GET_32BIT(state->state + 12);

  /* Get new key. */
  memcpy(state->stir_key, state->state, sizeof(state->stir_key));

  /* First pass. */
  for (i = 0; i < SSH_RANDOM_STATE_BYTES; i += 16)
    {
      ssh_md5_transform(iv, state->stir_key);
      iv[0] ^= SSH_GET_32BIT(state->state + i);
      SSH_PUT_32BIT(state->state + i, iv[0]);
      iv[1] ^= SSH_GET_32BIT(state->state + i + 4);
      SSH_PUT_32BIT(state->state + i + 4, iv[1]);
      iv[2] ^= SSH_GET_32BIT(state->state + i + 8);
      SSH_PUT_32BIT(state->state + i + 8, iv[2]);
      iv[3] ^= SSH_GET_32BIT(state->state + i + 12);
      SSH_PUT_32BIT(state->state + i + 12, iv[3]);
    }

  /* Get new key. */
  memcpy(state->stir_key, state->state, sizeof(state->stir_key));

  /* Second pass. */
  for (i = 0; i < SSH_RANDOM_STATE_BYTES; i += 16)
    {
      ssh_md5_transform(iv, state->stir_key);
      iv[0] ^= SSH_GET_32BIT(state->state + i);
      SSH_PUT_32BIT(state->state + i, iv[0]);
      iv[1] ^= SSH_GET_32BIT(state->state + i + 4);
      SSH_PUT_32BIT(state->state + i + 4, iv[1]);
      iv[2] ^= SSH_GET_32BIT(state->state + i + 8);
      SSH_PUT_32BIT(state->state + i + 8, iv[2]);
      iv[3] ^= SSH_GET_32BIT(state->state + i + 12);
      SSH_PUT_32BIT(state->state + i + 12, iv[3]);
    }
  
  memset(iv, 0, sizeof(iv));

  state->add_position = 0;

  /* Some data in the beginning is not returned to aboid giving an observer
     complete knowledge of the contents of our random pool. */
  state->next_available_byte = sizeof(state->stir_key);
}

/* Returns a random byte.  Stirs the pool if necessary.  If this is called
   repeatedly, a small of new environmental noise will automatically be
   acquired every few minutes. */

DLLEXPORT unsigned int DLLCALLCONV
ssh_random_get_byte(SshRandomState state)
{
  if (state->next_available_byte >= SSH_RANDOM_STATE_BYTES)
    ssh_random_stir(state);
  if (state->next_available_byte >= SSH_RANDOM_STATE_BYTES)
    ssh_fatal("ssh_random_get_byte: internal error.");
  return state->state[state->next_available_byte++];
}

/* Zeroes and frees any data structures associated with the random number
   generator.  This should be called when the state is no longer needed to
   remove any sensitive data from memory. */

DLLEXPORT void DLLCALLCONV
ssh_random_free(SshRandomState state)
{
  memset(state, 0, sizeof(*state));
  ssh_xfree(state);
}
