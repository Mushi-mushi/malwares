/*

userfile.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Jan 24 20:19:53 1996 ylo

*/

/*
 * $Id: sshuserfile.c,v 1.2 1999/03/30 05:56:33 tri Exp $
 * $Log: sshuserfile.c,v $
 * $EndLog$
 */

/* Protocol for communication between the child and the parent: 

      Each message starts with a 32-bit length (msb first; includes
      type but not length itself), followed by one byte containing
      the packet type.

        1 USERFILE_OPEN
          string        file name
          int32         flags
          int32         mode

        2 USERFILE_OPEN_REPLY
          int32         handle (-1 if error)

        3 USERFILE_READ
          int32         handle
          int32         max_bytes

        4 USERFILE_READ_REPLY
          string        data      ;; empty data means EOF

        5 USERFILE_WRITE
          int32         handle
          string        data

        6 USERFILE_WRITE_REPLY
          int32         bytes_written  ;; != length of data means error
        
        7 USERFILE_CLOSE
          int32         handle

        8 USERFILE_CLOSE_REPLY
          int32         return value

        9 USERFILE_LSEEK
          int32         handle
          int32         offset
          int32         whence

       10 USERFILE_LSEEK_REPLY
          int32         returned_offset

       11 USERFILE_MKDIR
          string        path
          int32         mode

       12 USERFILE_MKDIR_REPLY
          int32         return value

       13 USERFILE_STAT
          string        path

       14 USERFILE_STAT_REPLY
          int32         return value
          sizeof(struct stat) binary bytes (in host order and layout)

       15 USERFILE_REMOVE
          string        path

       16 USERFILE_REMOVE_REPLY
          int32         return value

       17 USERFILE_POPEN
          string        command
          string        type

       18 USERFILE_POPEN_REPLY
          int32         handle (-1 if error)

       19 USERFILE_PCLOSE
          int32         handle

       20 USERFILE_PCLOSE_REPLY
          int32         return value

       21 USERFILE_RENAME
          string        oldpath
          string        newpath

       22 USERFILE_RENAME_REPLY
          int32         return value

       23 USERFILE_SHARED_LOCK
          int32         handle
          int32         offset
          int32         length

       24 USERFILE_SHARED_LOCK_REPLY
          int32         return value
          
       25 USERFILE_EXCL_LOCK
          int32         handle
          int32         offset
          int32         length

       26 USERFILE_EXCL_LOCK_REPLY
          int32         return value
          
       27 USERFILE_UNLOCK
          int32         handle
          int32         offset
          int32         length

       28 USERFILE_UNLOCK_REPLY
          int32         return value

       29 USERFILE_GET_DES_1_MAGIC_PHRASE

       30 USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY
          string        data
          
          */

#include "sshincludes.h"
#include "sshuserfile.h"
#include "sshgetput.h"
#include "sshbuffer.h"
#include "sshbufaux.h"
#include "sshsignals.h"
#include "sshfilelock.h"

#ifdef SECURE_RPC
#include <rpc/rpc.h>
#endif


#if defined (__FreeBSD__) && defined(HAVE_LOGIN_CAP_H)
#include <login_cap.h>
#endif

/* Protocol message types. */
#define USERFILE_OPEN           1
#define USERFILE_OPEN_REPLY     2
#define USERFILE_READ           3
#define USERFILE_READ_REPLY     4
#define USERFILE_WRITE          5
#define USERFILE_WRITE_REPLY    6
#define USERFILE_CLOSE          7
#define USERFILE_CLOSE_REPLY    8
#define USERFILE_LSEEK          9
#define USERFILE_LSEEK_REPLY   10
#define USERFILE_MKDIR         11
#define USERFILE_MKDIR_REPLY   12
#define USERFILE_STAT          13
#define USERFILE_STAT_REPLY    14
#define USERFILE_REMOVE        15
#define USERFILE_REMOVE_REPLY  16
#define USERFILE_POPEN         17
#define USERFILE_POPEN_REPLY   18
#define USERFILE_PCLOSE        19
#define USERFILE_PCLOSE_REPLY  20
#define USERFILE_RENAME        21
#define USERFILE_RENAME_REPLY  22
#define USERFILE_SHARED_LOCK   23
#define USERFILE_SHARED_LOCK_REPLY 24
#define USERFILE_EXCL_LOCK     25
#define USERFILE_EXCL_LOCK_REPLY 26
#define USERFILE_UNLOCK        27
#define USERFILE_UNLOCK_REPLY  28
#define USERFILE_GET_DES_1_MAGIC_PHRASE        29
#define USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY  30


/* Flag indicating whether we have forked. */
static int ssh_userfile_initialized = 0;

/* The uid under which the child is running. */
static uid_t ssh_userfile_uid = -1;

/* Communication pipes. */
static int ssh_userfile_tochild;
static int ssh_userfile_fromchild;
static int ssh_userfile_toparent;
static int ssh_userfile_fromparent;

/* Aliases to above; set up depending on whether running as the server or
   the child. */
static int ssh_userfile_output;
static int ssh_userfile_input;

/* SshBuffer for a packet. */
static SshBuffer packet;
static int packet_initialized = 0;

/* Starts constructing a packet.  Stores the type into the packet. */

static void ssh_userfile_packet_start(int type)
{
  if (!packet_initialized)
    {
      ssh_buffer_init(&packet);
      packet_initialized = 1;
    }
  
  ssh_buffer_clear(&packet);
  buffer_put_char(&packet, type);
}

/* Sends a packet that has been constructed in "packet". */
  
static void ssh_userfile_packet_send(void)
{
  unsigned char lenbuf[4];
  unsigned int len, offset;
  int bytes;

  len = ssh_buffer_len(&packet);
  SSH_PUT_32BIT(lenbuf, len);
  len = 4;
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = write(ssh_userfile_output, lenbuf + offset, len - offset);
      if (bytes <= 0)
        ssh_fatal("ssh_userfile_packet_send: child has died: %s", strerror(errno));
    }
  
  len = ssh_buffer_len(&packet);
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = write(ssh_userfile_output, ssh_buffer_ptr(&packet) + offset, 
                    len - offset);
      if (bytes <= 0)
        ssh_fatal("ssh_userfile_packet_send: child has died: %s", strerror(errno));
    }
}

/* Reads a packet from the other side.  Returns the packet type. */

static int ssh_userfile_read_raw(void)
{
  unsigned char buf[512];
  unsigned int len, offset;
  int bytes;

  if (!packet_initialized)
    {
      ssh_buffer_init(&packet);
      packet_initialized = 1;
    }

  len = 4;
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = read(ssh_userfile_input, buf + offset, len - offset);
      if (bytes <= 0)
        {
          if (getuid() == geteuid()) /* presumably child - be quiet */
            exit(0);
          ssh_fatal("ssh_userfile_read_raw: child has died: %s", strerror(errno));
        }
    }

  len = SSH_GET_32BIT(buf);
  if (len > 32000)
    ssh_fatal("ssh_userfile_read_raw: received packet too long.");
  
  ssh_buffer_clear(&packet);
  for (offset = 0; offset < len; offset += bytes)
    {
      bytes = len - offset;
      if (bytes > sizeof(buf))
        bytes = sizeof(buf);
      bytes = read(ssh_userfile_input, buf, bytes);
      if (bytes <= 0)
        ssh_fatal("ssh_userfile_read_raw: child has died: %s", strerror(errno));
      ssh_buffer_append(&packet, buf, bytes);
    }
  return buffer_get_char(&packet);
}

/* Reads a packet from the child.  The packet should be of expected_type. */

static void ssh_userfile_packet_read(int expected_type)
{
  int type;

  type = ssh_userfile_read_raw();
  if (type != expected_type)
    ssh_fatal("ssh_userfile_read_packet: unexpected packet type: got %d, expected %d",
          type, expected_type);
}

/* Forks and execs the given command.  Returns a file descriptor for
   communicating with the program, or -1 on error.  The program will
   be run with empty environment to avoid LD_LIBRARY_PATH and similar
   attacks. */

int do_popen(const char *command, const char *type)
{
  int fds[2];
  int pid, i, j;
  char *args[100];
  char *env[100];
  extern char **environ;
  
  if (pipe(fds) < 0)
    ssh_fatal("pipe: %s", strerror(errno));
  
  pid = fork();
  if (pid < 0)
    ssh_fatal("fork: %s", strerror(errno));
  
  if (pid == 0)
    { /* Child */

      /* Close pipes to the parent; we do not wish to disclose them to a
         random user program. */
      close(ssh_userfile_fromparent);
      close(ssh_userfile_toparent);

      /* Set up file descriptors. */
      if (type[0] == 'r')
        {
          if (dup2(fds[1], 1) < 0)
            perror("dup2 1");
        }
      else
        {
          if (dup2(fds[0], 0) < 0)
            perror("dup2 0");
        }
      close(fds[0]);
      close(fds[1]);

      /* Build argument vector. */
      i = 0;
      args[i++] = "/bin/sh";
      args[i++] = "-c";
      args[i++] = (char *)command;
      args[i++] = NULL;

      /* Prune environment to remove any potentially dangerous variables. */
      i = 0;
      for (j = 0; environ[j] && i < sizeof(env)/sizeof(env[0]) - 1; j++)
        if (strncmp(environ[j], "HOME=", 5) == 0 ||
            strncmp(environ[j], "USER=", 5) == 0 ||
            strncmp(environ[j], "HOME=", 5) == 0 ||
            strncmp(environ[j], "PATH=", 5) == 0 ||
            strncmp(environ[j], "LOGNAME=", 8) == 0 ||
            strncmp(environ[j], "TZ=", 3) == 0 ||
            strncmp(environ[j], "MAIL=", 5) == 0 ||
            strncmp(environ[j], "SHELL=", 6) == 0 ||
            strncmp(environ[j], "TERM=", 5) == 0 ||
            strncmp(environ[j], "DISPLAY=", 8) == 0 ||
            strncmp(environ[j], "PRINTER=", 8) == 0 ||
            strncmp(environ[j], "XAUTHORITY=", 11) == 0 ||
            strncmp(environ[j], "TERMCAP=", 8) == 0)
          env[i++] = environ[j];
      env[i] = NULL;

      execve("/bin/sh", args, env);
      ssh_fatal("execv /bin/sh failed: %s", strerror(errno));
    }

  /* Parent. */
  if (type[0] == 'r')
    { /* It is for reading. */
      close(fds[1]);
      return fds[0];
    }
  else
    { /* It is for writing. */
      close(fds[0]);
      return fds[1];
    }
}

/* This function is the main loop of the child.  This never returns. */

static void ssh_userfile_child_server(void)
{
  int type, handle, ret, ret2;
  unsigned int max_bytes, flags, whence;
  size_t len; 
  mode_t mode;
  off_t offset;
  char *path, *newpath, *cp, *command;
  char buf[8192];
  struct stat st;

  for (;;)
    {
      type = ssh_userfile_read_raw();
      switch (type)
        {
        case USERFILE_OPEN:
          path = buffer_get_uint32_string(&packet, NULL);
          flags = buffer_get_int(&packet);
          mode = buffer_get_int(&packet);

          ret = open(path, flags, mode);

          ssh_userfile_packet_start(USERFILE_OPEN_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(path);
          break;

        case USERFILE_READ:
          handle = buffer_get_int(&packet);
          max_bytes = buffer_get_int(&packet);

          if (max_bytes >= sizeof(buf))
            max_bytes = sizeof(buf);
          ret = read(handle, buf, max_bytes);
          if (ret < 0)
            ret = 0;

          ssh_userfile_packet_start(USERFILE_READ_REPLY);
          buffer_put_uint32_string(&packet, buf, ret);
          ssh_userfile_packet_send();

          break;
          
        case USERFILE_WRITE:
          handle = buffer_get_int(&packet);
          cp = buffer_get_uint32_string(&packet, &len);

          ret = write(handle, cp, len);

          ssh_userfile_packet_start(USERFILE_WRITE_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(cp);
          break;

        case USERFILE_CLOSE:
          handle = buffer_get_int(&packet);

          ret = close(handle);

          ssh_userfile_packet_start(USERFILE_CLOSE_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          break;

        case USERFILE_LSEEK:
          handle = buffer_get_int(&packet);
          offset = buffer_get_int(&packet);
          whence = buffer_get_int(&packet);

          ret = lseek(handle, offset, whence);

          ssh_userfile_packet_start(USERFILE_LSEEK_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          break;

        case USERFILE_MKDIR:
          path = buffer_get_uint32_string(&packet, NULL);
          mode = buffer_get_int(&packet);

          ret = mkdir(path, mode);

          ssh_userfile_packet_start(USERFILE_MKDIR_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(path);
          break;

        case USERFILE_STAT:
          path = buffer_get_uint32_string(&packet, NULL);

          ret = stat(path, &st);

          ssh_userfile_packet_start(USERFILE_STAT_REPLY);
          buffer_put_int(&packet, ret);
          ssh_buffer_append(&packet, (void *)&st, sizeof(st));
          ssh_userfile_packet_send();

          ssh_xfree(path);
          break;
          
        case USERFILE_REMOVE:
          path = buffer_get_uint32_string(&packet, NULL);

          ret = remove(path);

          ssh_userfile_packet_start(USERFILE_REMOVE_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(path);
          break;

        case USERFILE_RENAME:
          path = buffer_get_uint32_string(&packet, NULL);
          newpath = buffer_get_uint32_string(&packet, NULL);

          ret = rename(path, newpath);

          ssh_userfile_packet_start(USERFILE_RENAME_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(path);
          ssh_xfree(newpath);
          break;
         
        case USERFILE_SHARED_LOCK:
          handle = buffer_get_int(&packet);
          offset = (off_t)buffer_get_int(&packet);
          len = buffer_get_int(&packet);

          ret = filelock_lock_shared(handle, offset, len);

          ssh_userfile_packet_start(USERFILE_SHARED_LOCK_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          break;
          
        case USERFILE_EXCL_LOCK:
          handle = buffer_get_int(&packet);
          offset = (off_t)buffer_get_int(&packet);
          len = buffer_get_int(&packet);

          ret = filelock_lock_exclusive(handle, offset, len);

          ssh_userfile_packet_start(USERFILE_EXCL_LOCK_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          break;
          
        case USERFILE_UNLOCK:
          handle = buffer_get_int(&packet);
          offset = (off_t)buffer_get_int(&packet);
          len = buffer_get_int(&packet);

          ret = filelock_unlock(handle, offset, len);

          ssh_userfile_packet_start(USERFILE_UNLOCK_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          break;
          
        case USERFILE_POPEN:
          command = buffer_get_uint32_string(&packet, NULL);
          cp = buffer_get_uint32_string(&packet, NULL);

          ret = do_popen(command, cp);

          ssh_userfile_packet_start(USERFILE_POPEN_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();

          ssh_xfree(command);
          ssh_xfree(cp);
          break;

        case USERFILE_PCLOSE:
          handle = buffer_get_int(&packet);

          ret = close(handle);
          ret2 = wait(NULL);
          if (ret >= 0)
            ret = ret2;

          ssh_userfile_packet_start(USERFILE_PCLOSE_REPLY);
          buffer_put_int(&packet, ret);
          ssh_userfile_packet_send();
          break;

        case USERFILE_GET_DES_1_MAGIC_PHRASE:
          {
            char *buf = NULL;
#ifdef SECURE_RPC
            buf = ssh_userfile_get_des_1_magic_phrase(geteuid());
#endif
            ssh_userfile_packet_start(USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY);
            if (buf == NULL)
              buffer_put_uint32_string(&packet, "", 0);
            else
              {
                buffer_put_uint32_string(&packet, buf, strlen(buf));
                memset(buf, 0, strlen(buf));
              }
            ssh_userfile_packet_send();
          }
          break;

        default:
          ssh_fatal("ssh_userfile_child_server: packet type %d", type);
        }
    }
}

/* Initializes reading as a user.  Before calling this, I/O may only be
   performed as the user that is running the current program (current
   effective uid).  SIGPIPE should be set to ignored before this call.
   The cleanup callback will be called in the child before switching to the
   user's uid.  The callback may be NULL. */

void ssh_userfile_init(const char *username, uid_t uid, gid_t gid,
                   void (*cleanup_callback)(void *), void *context)
{
  int fds[2], pid;

  if (ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_init already called");
  
  ssh_userfile_uid = uid;
  ssh_userfile_initialized = 1;

  if (pipe(fds) < 0)
    ssh_fatal("pipe: %s", strerror(errno));
  ssh_userfile_tochild = fds[1];
  ssh_userfile_fromparent = fds[0];
  
  if (pipe(fds) < 0)
    ssh_fatal("pipe: %s", strerror(errno));
  ssh_userfile_fromchild = fds[0];
  ssh_userfile_toparent = fds[1];
  
  pid = fork();
  if (pid < 0)
    ssh_fatal("fork: %s", strerror(errno));

  if (pid != 0)
    { 
      /* Parent. */
      ssh_userfile_input = ssh_userfile_fromchild;
      ssh_userfile_output = ssh_userfile_tochild;
      close(ssh_userfile_toparent);
      close(ssh_userfile_fromparent);
      return;
    }

  /* Child. */
  ssh_userfile_input = ssh_userfile_fromparent;
  ssh_userfile_output = ssh_userfile_toparent;
  close(ssh_userfile_tochild);
  close(ssh_userfile_fromchild);

  /* Call the cleanup callback if given. */
  if (cleanup_callback)
    (*cleanup_callback)(context);
  
  /* Reset signals to their default settings. */
  ssh_signals_reset();

  /* Child.  We will start serving request. */
  if (uid != geteuid() || uid != getuid())
    {
#if defined (__FreeBSD__) && defined(HAVE_LOGIN_CAP_H)
      struct passwd * pw = getpwuid(uid);
      login_cap_t * lc = login_getuserclass(pw);
      if (setusercontext(lc, pw, uid,
                         LOGIN_SETALL & ~(LOGIN_SETLOGIN | LOGIN_SETPATH |
                                          LOGIN_SETENV)) < 0)
        ssh_fatal("setusercontext: %s", strerror(errno));
#else
      if (setgid(gid) < 0)
        ssh_fatal("setgid: %s", strerror(errno));

#ifdef HAVE_INITGROUPS
      if (initgroups((char *) username, gid) < 0)
        ssh_fatal("initgroups: %s", strerror(errno));
#endif /* HAVE_INITGROUPS */

      if (setuid(uid) < 0)
        ssh_fatal("setuid: %s", strerror(errno));
#endif /* HAVE_LOGIN_CAP_H */
    }

  /* Enter the server main loop. */
  ssh_userfile_child_server();
}

/* Closes any open pipes held by userfile.  This should be called
   after a fork while the userfile is open. */

void ssh_userfile_close_pipes(void)
{
  if (!ssh_userfile_initialized)
    return;
  ssh_userfile_initialized = 0;
  close(ssh_userfile_fromchild);
  close(ssh_userfile_tochild);
}

/* Stops reading files as an ordinary user.  It is not an error to call
   this even if the system is not initialized. */

void ssh_userfile_uninit(void)
{
  int status;

  if (!ssh_userfile_initialized)
    return;
  
  ssh_userfile_close_pipes();

  wait(&status);
}

/* Data structure for SshUserFiles. */

struct SshUserFile
{
  enum { USERFILE_LOCAL, USERFILE_REMOTE } type;
  int handle; /* Local: file handle; remote: index to descriptor array. */
  unsigned char buf[512];
  unsigned int buf_first;
  unsigned int buf_last;
};

/* Allocates a SshUserFile handle and initializes it. */

static SshUserFile ssh_userfile_make_handle(int type, int handle)
{
  SshUserFile uf;

  uf = ssh_xmalloc(sizeof(*uf));
  uf->type = type;
  uf->handle = handle;
  uf->buf_first = 0;
  uf->buf_last = 0;
  return uf;
}
 
/* Encapsulate a normal file descriptor inside a struct SshUserFile. */

SshUserFile ssh_userfile_encapsulate_fd(int fd)
{
  return ssh_userfile_make_handle(USERFILE_LOCAL, fd);
}

/* Opens a file using the given uid.  The uid must be either the current
   effective uid (in which case ssh_userfile_init need not have been called) or
   the uid passed to a previous call to ssh_userfile_init.  Returns a pointer
   to a structure, or NULL if an error occurred.  The flags and mode arguments
   are identical to open(). */

SshUserFile ssh_userfile_open(uid_t uid, const char *path, int flags, mode_t mode)
{
  int handle;

  if (uid == geteuid())
    {
      handle = open(path, flags, mode);
      if (handle < 0)
        return NULL;
      return ssh_userfile_make_handle(USERFILE_LOCAL, handle);
    }

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_open: using non-current uid but not initialized "
              "(uid=%d, path=%.50s)",
              (int)uid, path);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_open: uid not current and not that of child: "
              "uid=%d, path=%.50s",
              (int)uid, path);

  ssh_userfile_packet_start(USERFILE_OPEN);
  buffer_put_uint32_string(&packet, path, strlen(path));
  buffer_put_int(&packet, flags);
  buffer_put_int(&packet, mode);
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_OPEN_REPLY);
  handle = buffer_get_int(&packet);
  if (handle < 0)
    return NULL;

  return ssh_userfile_make_handle(USERFILE_REMOTE, handle);
}

/* Closes the userfile handle.  Returns >= 0 on success, and < 0 on error. */

int ssh_userfile_close(SshUserFile uf)
{
  int ret;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = close(uf->handle);
      ssh_xfree(uf);
      return ret;

    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_CLOSE);
      buffer_put_int(&packet, uf->handle);
      ssh_userfile_packet_send();
      
      ssh_userfile_packet_read(USERFILE_CLOSE_REPLY);
      ret = buffer_get_int(&packet);

      ssh_xfree(uf);
      return ret;

    default:
      ssh_fatal("ssh_userfile_close: type %d", uf->type);
      /*NOTREACHED*/
      return -1;
    }
}

/* Invalidate the buffer in case of lseek(). */

static void ssh_userfile_invalidate_buffer(SshUserFile uf)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      uf->buf_first = 0;
      uf->buf_last = 0;
      break;
      
    case USERFILE_REMOTE:
      ssh_fatal("Don't know how to invalidate the remote UF buffer.");
      /* NOTREACHED */
    }
}

/* Get more data from the child into the buffer.  Returns false if no more
   data is available (EOF). */

static int ssh_userfile_fill(SshUserFile uf)
{
  size_t len;
  char *cp;
  int ret;

  if (uf->buf_first < uf->buf_last)
    ssh_fatal("ssh_userfile_fill: buffer not empty");

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = read(uf->handle, uf->buf, sizeof(uf->buf));
      if (ret <= 0)
        return 0;
      uf->buf_first = 0;
      uf->buf_last = ret;
      break;

    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_READ);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, sizeof(uf->buf));
      ssh_userfile_packet_send();

      ssh_userfile_packet_read(USERFILE_READ_REPLY);
      cp = buffer_get_uint32_string(&packet, &len);
      if (len > sizeof(uf->buf))
        ssh_fatal("ssh_userfile_fill: got more than data than requested");
      memcpy(uf->buf, cp, len);
      ssh_xfree(cp);
      if (len == 0)
        return 0;
      uf->buf_first = 0;
      uf->buf_last = len;
      break;

    default:
      ssh_fatal("ssh_userfile_fill: type %d", uf->type);
    }

  return 1;
}

/* Returns the next character from the file (as an unsigned integer) or -1
   if an error is encountered. */

int ssh_userfile_getc(SshUserFile uf)
{
  if (uf->buf_first >= uf->buf_last)
    {
      if (!ssh_userfile_fill(uf))
        return -1;
      
      if (uf->buf_first >= uf->buf_last)
        ssh_fatal("ssh_userfile_getc/fill error");
    }
  
  return uf->buf[uf->buf_first++];
}

/* Reads data from the file.  Returns as much data as is the buffer
   size, unless end of file is encountered.  Returns the number of bytes
   read, 0 on EOF, and -1 on error. */

int ssh_userfile_read(SshUserFile uf, void *buf, unsigned int len)
{
  unsigned int i;
  int ch;
  unsigned char *ucp;

  ucp = buf;
  for (i = 0; i < len; i++)
    {
      ch = ssh_userfile_getc(uf);
      if (ch == -1)
        break;
      ucp[i] = ch;
    }

  return i;
}

/* Writes data to the file.  Writes all data, unless an error is encountered.
   Returns the number of bytes actually written; -1 indicates error. */

int ssh_userfile_write(SshUserFile uf, const void *buf, unsigned int len)
{
  unsigned int chunk_len, offset;
  int ret;
  const unsigned char *ucp;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return write(uf->handle, buf, len);
      
    case USERFILE_REMOTE:
      ucp = buf;
      for (offset = 0; offset < len; )
        {
          chunk_len = len - offset;
          if (chunk_len > 16000)
            chunk_len = 16000;
          
          ssh_userfile_packet_start(USERFILE_WRITE);
          buffer_put_int(&packet, uf->handle);
          buffer_put_uint32_string(&packet, ucp + offset, chunk_len);
          ssh_userfile_packet_send();
          
          ssh_userfile_packet_read(USERFILE_WRITE_REPLY);
          ret = buffer_get_int(&packet);
          if (ret < 0)
            return -1;
          offset += ret;
          if (ret != chunk_len)
            break;
        }
      return offset;

    default:
      ssh_fatal("ssh_userfile_write: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

/* Reads a line from the file.  The line will be null-terminated, and
   will include the newline.  Returns a pointer to the given buffer,
   or NULL if no more data was available.  If a line is too long,
   reads as much as the buffer can accommodate (and null-terminates
   it).  If the last line of the file does not terminate with a
   newline, returns the line, null-terminated, but without a
   newline. */

char *ssh_userfile_gets(char *buf, unsigned int size, SshUserFile uf)
{
  unsigned int i;
  int ch;

  for (i = 0; i < size - 1; )
    {
      ch = ssh_userfile_getc(uf);
      if (ch == -1)
        break;
      buf[i++] = ch;
      if (ch == '\n')
        break;
    }
  if (i == 0)
    return NULL;

  buf[i] = '\0';
  
  return buf;
}

/* Performs lseek() on the given file. */

off_t ssh_userfile_lseek(SshUserFile uf, off_t offset, int whence)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ssh_userfile_invalidate_buffer(uf);
      return lseek(uf->handle, offset, whence);
      
    case USERFILE_REMOTE:
      ssh_userfile_invalidate_buffer(uf);
      ssh_userfile_packet_start(USERFILE_LSEEK);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, offset);
      buffer_put_int(&packet, whence);
      ssh_userfile_packet_send();

      ssh_userfile_packet_read(USERFILE_LSEEK_REPLY);
      return buffer_get_int(&packet);

    default:
      ssh_fatal("ssh_userfile_lseek: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

/* Creates a directory using the given uid. */

int ssh_userfile_mkdir(uid_t uid, const char *path, mode_t mode)
{
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return mkdir(path, mode);

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_mkdir with uid %d", (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_mkdir with wrong uid %d", (int)uid);

  ssh_userfile_packet_start(USERFILE_MKDIR);
  buffer_put_uint32_string(&packet, path, strlen(path));
  buffer_put_int(&packet, mode);
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_MKDIR_REPLY);
  return buffer_get_int(&packet);
}

/* Performs stat() using the given uid. */

int ssh_userfile_stat(uid_t uid, const char *path, struct stat *st)
{
  int ret;

  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return stat(path, st);

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_stat with uid %d", (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_stat with wrong uid %d", (int)uid);

  ssh_userfile_packet_start(USERFILE_STAT);
  buffer_put_uint32_string(&packet, path, strlen(path));
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_STAT_REPLY);
  ret = buffer_get_int(&packet);
  ssh_buffer_get(&packet, (unsigned char *)st, sizeof(*st));

  return ret;
}

/* Performs remove() using the given uid. */

int ssh_userfile_remove(uid_t uid, const char *path)
{
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return remove(path);

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_remove with uid %d", (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_remove with wrong uid %d", (int)uid);

  ssh_userfile_packet_start(USERFILE_REMOVE);
  buffer_put_uint32_string(&packet, path, strlen(path));
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_REMOVE_REPLY);
  return buffer_get_int(&packet);
}

/* Performs rename() using the given uid. */

int ssh_userfile_rename(uid_t uid, const char *oldpath, const char *newpath)
{
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    return rename(oldpath, newpath);

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_rename with uid %d", (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_rename with wrong uid %d", (int)uid);

  ssh_userfile_packet_start(USERFILE_RENAME);
  buffer_put_uint32_string(&packet, oldpath, strlen(oldpath));
  buffer_put_uint32_string(&packet, newpath, strlen(newpath));
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_RENAME_REPLY);
  return buffer_get_int(&packet);
}

/* Performs file locking using the given uid */

int ssh_userfile_lock_shared(SshUserFile uf, off_t offset, off_t len)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return filelock_lock_shared(uf->handle, offset, len);
      
    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_SHARED_LOCK);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, offset);
      buffer_put_int(&packet, len);
      ssh_userfile_packet_send();

      ssh_userfile_packet_read(USERFILE_SHARED_LOCK_REPLY);
      return buffer_get_int(&packet);

    default:
      ssh_fatal("ssh_userfile_lock_shared: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

int ssh_userfile_lock_exclusive(SshUserFile uf, off_t offset, off_t len)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return filelock_lock_exclusive(uf->handle, offset, len);
      
    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_EXCL_LOCK);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, offset);
      buffer_put_int(&packet, len);
      ssh_userfile_packet_send();

      ssh_userfile_packet_read(USERFILE_EXCL_LOCK_REPLY);
      return buffer_get_int(&packet);

    default:
      ssh_fatal("ssh_userfile_lock_exclusive: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

int ssh_userfile_unlock(SshUserFile uf, off_t offset, off_t len)
{
  switch (uf->type)
    {
    case USERFILE_LOCAL:
      return filelock_unlock(uf->handle, offset, len);

    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_UNLOCK);
      buffer_put_int(&packet, uf->handle);
      buffer_put_int(&packet, offset);
      buffer_put_int(&packet, len);
      ssh_userfile_packet_send();

      ssh_userfile_packet_read(USERFILE_UNLOCK_REPLY);
      return buffer_get_int(&packet);

    default:
      ssh_fatal("ssh_userfile_unlock: type %d", uf->type);
      /*NOTREACHED*/
      return 0;
    }
}

/* Performs popen() on the given uid; returns a file from where the output
   of the command can be read (type == "r") or to where data can be written
   (type == "w"). */

SshUserFile ssh_userfile_popen(uid_t uid, const char *command, const char *type)
{
  int handle;

  if (uid == geteuid())
    {
      handle = do_popen(command, type);
      if (handle < 0)
        return NULL;
      return ssh_userfile_make_handle(USERFILE_LOCAL, handle);
    }

  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_popen: using non-current uid but not initialized (uid=%d)",
          (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_popen: uid not current and not that of child: uid=%d",
          (int)uid);

  ssh_userfile_packet_start(USERFILE_POPEN);
  buffer_put_uint32_string(&packet, command, strlen(command));
  buffer_put_uint32_string(&packet, type, strlen(type));
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_POPEN_REPLY);
  handle = buffer_get_int(&packet);
  if (handle < 0)
    return NULL;

  return ssh_userfile_make_handle(USERFILE_REMOTE, handle);
}

/* Performs pclose() on the given uid.  Returns <0 if an error occurs. */

int ssh_userfile_pclose(SshUserFile uf)
{
  int ret, ret2;

  switch (uf->type)
    {
    case USERFILE_LOCAL:
      ret = close(uf->handle);
      ret2 = wait(NULL);
      if (ret >= 0)
        ret = ret2;
      ssh_xfree(uf);
      return ret;

    case USERFILE_REMOTE:
      ssh_userfile_packet_start(USERFILE_PCLOSE);
      buffer_put_int(&packet, uf->handle);
      ssh_userfile_packet_send();
      
      ssh_userfile_packet_read(USERFILE_PCLOSE_REPLY);
      ret = buffer_get_int(&packet);

      ssh_xfree(uf);
      return ret;

    default:
      ssh_fatal("ssh_userfile_close: type %d", uf->type);
      /*NOTREACHED*/
      return -1;
    }
}

/* Get sun des 1 magic phrase */

char *ssh_userfile_get_des_1_magic_phrase(uid_t uid)
{
  char *phrase = NULL;
#ifdef SECURE_RPC
  /* Perform directly if with current effective uid. */
  if (uid == geteuid())
    {
      char buf[MAXNETNAMELEN + 1];
      des_block block;
      
      memset(buf, 0, sizeof(buf));
      snprintf(buf, sizeof(buf), "ssh.%04X", geteuid());
      memcpy(block.c, buf, sizeof(block.c));
      if (getnetname(buf))
        {
          if (key_encryptsession(buf, &block) == 0)
            {
              snprintf(buf, sizeof(buf), "%08X%08X", ntohl(block.key.high),
                       ntohl(block.key.low));
              memset(block.c, 0, sizeof(block.c));
              phrase = ssh_xstrdup(buf);
              memset(buf, 0, sizeof(buf));
            }
        }
      return phrase;
    }
  
  if (!ssh_userfile_initialized)
    ssh_fatal("ssh_userfile_get_des_1_magic_phrase with uid %d", (int)uid);
  
  if (uid != ssh_userfile_uid)
    ssh_fatal("ssh_userfile_get_des_1_magic_phrase with wrong uid %d", (int)uid);

  ssh_userfile_packet_start(USERFILE_GET_DES_1_MAGIC_PHRASE);
  ssh_userfile_packet_send();

  ssh_userfile_packet_read(USERFILE_GET_DES_1_MAGIC_PHRASE_REPLY);
  phrase = buffer_get_uint32_string(&packet, NULL);
  if (strlen(phrase) == 0)
    {
      ssh_xfree(phrase);
      return NULL;
    }
  return phrase;
#else /* SECURE_RPC */
  return phrase;
#endif /* SECURE_RPC */
}

#ifndef UID_ROOT
#define UID_ROOT 0
#endif /* UID_ROOT */

int ssh_userfile_check_owner_permissions(struct passwd *pw, const char *path)
{
  struct stat st;
  if (ssh_userfile_stat(pw->pw_uid, path, &st) < 0)
    return 0;

  if ((st.st_uid != UID_ROOT && st.st_uid != pw->pw_uid) ||
#ifdef ALLOW_GROUP_WRITEABILITY
      (st.st_mode & 002) != 0
#else /* ALLOW_GROUP_WRITEABILITY */
      (st.st_mode & 022) != 0
#endif /* ALLOW_GROUP_WRITEABILITY */
      )
    return 0;
  else
    return 1;
}
