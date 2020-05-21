/*

  sshfilexfers.c

  Author: Tatu Ylonen <ylo@ssh.fi>
          
  Copyright (c) 1998 SSH Communications Security, Finland
                     All rights reserved

  Generic file transfer module, client side.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshpacketstream.h"
#include "sshfilexfer.h"
#include "sshfilexferi.h"

/* Data structure for a server-side file handle.  This definition is
   private to the implementation. */

typedef struct SshServerHandleRec
{
  /* Pointer to next handle for this server. */
  struct SshServerHandleRec *next;

  /* Value of the file handle when passed to the client.  This value identifies
     the handle uniquely among handles for this server. */
  unsigned char *value;

  /* Length of the handle value. */
  size_t len;

  /* Flag indicating whether the handle refers to a directory. */
  Boolean is_directory;

  /* If the handle refers to a file, this is the file handle for the open
     file. */
  int fd;

  /* This is the name of the file / directory */  
  char *name;
  
  /* If the handle refers to a directory, this is a directory pointer for
     the directory as returned by opendir. */
  DIR *dir;
} *SshServerHandle;

/* Data structure for the file transfer server. */

struct SshFileServerRec
{
  /* Connection to the client. */
  SshPacketWrapper conn;

  /* List of open file handles. */
  SshServerHandle handles;
};

/* Create a new file handle and add it to the list of handles.  This
   returns the new handle. */

SshServerHandle ssh_file_server_new_handle(SshFileServer server,
                                           Boolean is_directory,
                                           char *name, 
                                           void *fd)
{
  SshServerHandle handle;

  /* Allocate space for the handle structure. */
  handle = ssh_xmalloc(sizeof(*handle));

  /* Create a string that is used as the handle.  We include the memory
     address of the handle object and the file descriptor. */
  handle->len = ssh_encode_alloc(&handle->value,
                                 SSH_FORMAT_UINT32, (SshUInt32) handle,
                                 SSH_FORMAT_UINT32, (SshUInt32) fd,
                                 SSH_FORMAT_END);

  /* Set up other fields of the handle structure. */
  handle->is_directory = is_directory;
  if (is_directory)
    handle->dir = (DIR *)fd;
  else
    handle->fd = (int)fd;

  if (name == NULL)
    handle->name = NULL;
  else
    handle->name = ssh_xstrdup(name);
  
  /* Add to the list of open file handles. */
  handle->next = server->handles;
  server->handles = handle;

  /* Return the handle. */
  return handle;
}

/* Looks up the file handle with the given value.  Returns the handle,
   or NULL if no such handle exists. */

SshServerHandle ssh_file_server_find_handle(SshFileServer server,
                                            const unsigned char *value,
                                            size_t len)
{
  SshServerHandle handle;

  /* Go over the list of handles, comparing the value in each
     handle. */
  for (handle = server->handles; handle; handle = handle->next)
    {
      if (handle->len == len && memcmp(handle->value, value, len) == 0)
        return handle; /* Found - return the handle. */
    }

  /* No such handle exists. */
  ssh_warning("ssh_file_server_find_handle: handle not found");
  return NULL;
}

/* Frees the given handle and removes it from the list of handles. */

void ssh_file_server_free_handle(SshFileServer server, SshServerHandle handle)
{
  SshServerHandle *handlep;

  for (handlep = &server->handles; *handlep; handlep = &(*handlep)->next)
    if (*handlep == handle)
      {
        *handlep = handle->next;
        ssh_xfree(handle->value);
        ssh_xfree(handle->name);
        ssh_xfree(handle);
        return;
      }
          
  ssh_warning("ssh_file_server_free_handle: handle not found");
}

/* Formats and sends a message to the client. */

void ssh_file_server_send(SshFileServer server, SshPacketType type, ...)
{
  va_list va;

  va_start(va, type);
  ssh_packet_wrapper_send_encode_va(server->conn, type, va);
  va_end(va);
}

/* Sends a status message to the client. */

void ssh_file_server_send_status(SshFileServer server, unsigned long id,
                                 SshFileClientError error)
{
  ssh_file_server_send(server, SSH_FXP_STATUS,
                       SSH_FORMAT_UINT32, (SshUInt32) id,
                       SSH_FORMAT_UINT32, (SshUInt32) error,
                       SSH_FORMAT_END);
}

/* Converts an errno value to a file transfer protocol error code. */

int ssh_file_server_errno_to_error(int errno_value)
{
  switch (errno_value)
    {
    case ENOENT:
      return SSH_FX_NO_SUCH_FILE;
    case EPERM:
      return SSH_FX_PERMISSION_DENIED;
    case EACCES:
      return SSH_FX_PERMISSION_DENIED;
    default:
      return SSH_FX_FAILURE;
    }
}

/* This callback function is called whenever a packet is received from
   the client. */

void ssh_file_server_receive_proc(SshPacketType type,
                                  const unsigned char *data, size_t len,
                                  void *context)
{
  SshFileServer server = (SshFileServer)context;
  size_t valuelen, iodatalen;
  SshUInt32 version, id, pflags, iolen;
  unsigned long flags;
  SshUInt64 offset;
  long ret;
  char *name;  
  unsigned char *value, *iodata;
  SshFileAttributes attrs;
  SshServerHandle handle;
  int fd;
  SshFileClientError error;
  struct stat st;
  DIR *dir;
  struct dirent *dp;
  SshBuffer buffer;
  int i;
  char resolved[MAXPATHLEN];

#if defined(HAVE_LUTIMES) || defined(HAVE_FUTIMES) || defined(HAVE_UTIMES)
  struct timeval times[2];
#endif /* HAVE_LUTIMES || HAVE_FUTIMES || HAVE_UTIMES */

#if defined(HAVE_UTIME) && !defined(HAVE_LUTIMES)
  struct utimbuf timep;
#endif /* HAVE_UTIME && !HAVE_LUTIMES */

#ifndef NO_LONG_NAMES
#ifdef HAVE_GETPWUID
  struct passwd *pw;
#endif /* HAVE_GETPWUID */
#ifdef HAVE_GETGRGID
  struct group *gr;
#endif /* HAVE_GETGRGID */
  struct SshCalendarTimeRec tm[1];
  int    this_year;  
  SshTime tim;
  char   user_name[32];
  char   group_name[32];  
  char   date_string[32];
  char   name_ext[128];
  char   long_name[256];
  const char *month_name[12] = 
  {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" 
  };
#endif /* NO_LONG_NAMES */
  
  attrs = ssh_xcalloc(1, sizeof(struct SshFileAttributesRec));
  
  switch (type)
    {
    case SSH_FXP_INIT:
      /* Parse the INIT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &version,
                           SSH_FORMAT_END) != len)
        {
          /* Did not parse. */
          ssh_warning("ssh_file_server_receive_proc: bad INIT");
          break;
        }

      /* Compute the protocol version to use. */
      version = (version < SSH_FILEXFER_VERSION) ? version :
        SSH_FILEXFER_VERSION;

      /* Send a version response message to the client. */
      ssh_file_server_send(server, SSH_FXP_VERSION,
                           SSH_FORMAT_UINT32, version,
                           SSH_FORMAT_END);
      break;

    case SSH_FXP_OPEN:
      /* Parse the OPEN message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_UINT32, &pflags,
                           SSH_FORMAT_EXTENDED, 
                           ssh_file_attrs_decoder, &attrs,
                           SSH_FORMAT_END) != len)
        {
          /* Did not parse... */
          ssh_warning("ssh_file_server_receive_proc: bad OPEN");
        return_bad_status:
          /* Send back a status message indicating badly formatted
             message.  Note that we are actually optimistic here and
             assume that id got properly parsed.  This shouldn't
             cause any fatal problems even if it wasn't (the client just
             won't be able to associate the reply with the correct
             request), but the alternative would be causing the client
             to hang. */
          ssh_file_server_send_status(server, id, SSH_FX_BAD_MESSAGE);
          break;
        }

      /* Convert portable represenation of flags into the appropriate
         flags for this machine. */
      switch (pflags & (SSH_FXF_READ|SSH_FXF_WRITE))
        {
        case SSH_FXF_READ:
          flags = O_RDONLY;
          break;
        case SSH_FXF_WRITE:
          flags = O_WRONLY;
          break;
        case SSH_FXF_READ|SSH_FXF_WRITE:
          flags = O_RDWR;
          break;
        default:
          flags = 0;
        }
      if (pflags & SSH_FXF_APPEND)
        flags |= O_APPEND;
      if (pflags & SSH_FXF_CREAT)
        flags |= O_CREAT;
      if (pflags & SSH_FXF_TRUNC)
        flags |= O_TRUNC;
      if (pflags & SSH_FXF_EXCL)
        flags |= O_EXCL;

      /* Try to open the file. */
      fd = open(name, flags,
                (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) ?
                attrs->permissions : 0666);
      
      /* Check whether the open was successful. */
      if (fd < 0)
        {
          /* Open failed.  Compute error code to return to client. */
          ssh_file_server_send_status(server, id,
                                      ssh_file_server_errno_to_error(errno));
          ssh_xfree(name);
          break;
        }

      /* If the attributes specify uid and gid, try to switch to them. */
      if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
        {
#ifdef HAVE_FCHOWN
          /* Note: we ignore the return value. */
          fchown(fd, attrs->uid, attrs->gid);
#endif /* HAVE_FCHOWN */
        }

      /* Open was successful.  Wrap the real file handle to a handle object. */
      handle = ssh_file_server_new_handle(server, FALSE, name, (void *)fd);

      /* Free the allocated file name. */
      ssh_xfree(name);
      
      /* Send a handle message to the client. */
      ssh_file_server_send(server, SSH_FXP_HANDLE,
                           SSH_FORMAT_UINT32, id,
                           SSH_FORMAT_UINT32_STR, handle->value, handle->len,
                           SSH_FORMAT_END);
      break;

    case SSH_FXP_CLOSE:
      /* Parse the CLOSE message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad CLOSE");
          goto return_bad_status;
        }

      /* Look up the file handle. */
      handle = ssh_file_server_find_handle(server, value, valuelen);

      /* If the handle was not found, return error. */
      if (!handle)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      /* Close the file descriptor.  Note that the close can meaningfully
         return an error e.g. on NFS file systems. */
      if (handle->is_directory)
        ret = closedir(handle->dir);
      else
        ret = close(handle->fd);

      if (ret < 0)
        error = ssh_file_server_errno_to_error(errno);
      else
        error = SSH_FX_OK;

      /* Free the handle structure (and remove from the server list). */
      ssh_file_server_free_handle(server, handle);

      /* Send a status message to the client. */
      ssh_file_server_send_status(server, id, error);
      break;
      
    case SSH_FXP_READ:
      /* Parse the READ message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_UINT64, &offset,
                           SSH_FORMAT_UINT32, &iolen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad READ");
          goto return_bad_status;
        }

      /* Look up the handle.  If not found, return error status. */
      handle = ssh_file_server_find_handle(server, value, valuelen);
      if (!handle || handle->is_directory)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      /* Try to read from the file. */
      if (iolen > XMALLOC_MAX_SIZE)
        iolen = XMALLOC_MAX_SIZE;
      if (iolen > 100000)
        iolen = 100000;

      /* Allocate memory for a buffer. */
      value = ssh_xmalloc(iolen);

      /* Seek to the specified location in the file. */
      lseek(handle->fd, (off_t)offset, SEEK_SET);

      /* Perform the actual read. */
      ret = read(handle->fd, value, iolen);

      /* If read failed, return error. */
      if (ret <= 0)
        {
          ssh_xfree(value);
          ssh_file_server_send_status(server, id,
                                      (ret == 0 ? SSH_FX_EOF :
                                       SSH_FX_FAILURE));
          break;
        }

      /* Send the data to the client. */
      ssh_file_server_send(server, SSH_FXP_DATA,
                           SSH_FORMAT_UINT32, id,
                           SSH_FORMAT_UINT32_STR, value, (size_t)ret,
                           SSH_FORMAT_END);

      /* Free the allocated buffer. */
      ssh_xfree(value);
      break;

    case SSH_FXP_WRITE:
      /* Parse the WRITE message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_UINT64, &offset,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &iodata, &iodatalen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad WRITE");
          goto return_bad_status;
        }

      /* Look up the handle.  If not found, return error status. */
      handle = ssh_file_server_find_handle(server, value, valuelen);
      if (!handle || handle->is_directory)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      /* Seek to the specified location in the file. */
      lseek(handle->fd, (off_t)offset, SEEK_SET);
      
      /* Perform the actual write. */
      ret = write(handle->fd, iodata, iodatalen);

      /* Report status back to the client. */
      if (ret != iodatalen)
        ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
      else
        ssh_file_server_send_status(server, id, SSH_FX_OK);
      break;

    case SSH_FXP_STAT:
      /* Parse the STAT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad STAT");
          goto return_bad_status;
        }

      /* Stat the given file. */
      if (stat(name, &st) < 0)
        {
          /* Stat failed. */
          ssh_file_server_send_status(server, id,
                                      ssh_file_server_errno_to_error(errno));
          ssh_xfree(name);
          break;
        }

      /* Free the file name. */
      ssh_xfree(name);

    return_stat:
      attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
        SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
      attrs->size = st.st_size;
      attrs->uid = st.st_uid;
      attrs->gid = st.st_gid;
      attrs->permissions = st.st_mode;
      attrs->atime = st.st_atime;
      attrs->mtime = st.st_mtime;
      ssh_file_server_send(server, SSH_FXP_ATTRS,
                           SSH_FORMAT_UINT32, id,
                           SSH_FORMAT_EXTENDED, 
                           ssh_file_attrs_encoder, attrs,
                           SSH_FORMAT_END);
      break;

    case SSH_FXP_LSTAT:
#ifdef HAVE_LSTAT
      /* Parse the LSTAT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad LSTAT");
          goto return_bad_status;
        }

      /* Stat the given file. */
      if (lstat(name, &st) < 0)
        {
          /* Stat failed. */
          ssh_file_server_send_status(server, id,
                                      ssh_file_server_errno_to_error(errno));
          ssh_xfree(name);
          break;
        }

      /* Free the file name. */
      ssh_xfree(name);

      goto return_stat;
      
#else /* HAVE_LSTAT */
      ssh_warning("ssh_file_server_receive_proc: no lstat on this platform");
      ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
      break;
#endif /* HAVE_LSTAT */

    case SSH_FXP_FSTAT:
#ifdef HAVE_FSTAT
      /* Parse the FSTAT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad FSTAT");
          goto return_bad_status;
        }

      /* Look up the handle.  If not found, return error status. */
      handle = ssh_file_server_find_handle(server, value, valuelen);
      if (!handle || handle->is_directory)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      if (fstat(handle->fd, &st) < 0)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }
      goto return_stat;

#else /* HAVE_FSTAT */
      ssh_warning("ssh_file_server_receive_proc: no fstat on this platform");
      ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
      break;
#endif /* HAVE_FSTAT */

    case SSH_FXP_SETSTAT:
      /* Parse the SETSTAT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_EXTENDED, ssh_file_attrs_decoder, &attrs,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad SETSTAT");
          goto return_bad_status;
        }

      ret = 0;
      if (attrs->flags & SSH_FILEXFER_ATTR_SIZE)
        {
#ifdef HAVE_TRUNCATE
          if (truncate(name, attrs->size) < 0)
            ret = -1;
#else /* HAVE_TRUNCATE */
          ssh_warning("ssh_file_server_receive_proc: no truncate on this platform");
          ret = -1;
#endif /* HAVE_TRUNCATE */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
        {
#ifdef HAVE_CHOWN
          if (chown(name, attrs->uid, attrs->gid) < 0)
            ret = -1;
#else /* HAVE_CHOWN */
          ret = -1;
#endif /* HAVE_CHOWN */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        {
#ifdef HAVE_CHMOD
          if (chmod(name, attrs->permissions) < 0)
            ret = -1;
#else /* HAVE_CHMOD */
          ret = -1;
#endif /* HAVE_CHMOD */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
        {
#if defined(HAVE_LUTIMES) || defined(HAVE_UTIMES)
          times[0].tv_sec = attrs->atime;
          times[1].tv_sec = attrs->mtime;
          times[0].tv_usec = times[1].tv_usec = 0L;

          if (
#ifdef HAVE_LUTIMES
              lutimes(name, times)
#else /* HAVE_LUTIMES */
              utimes(name, times)
#endif /* HAVE_LUTIMES */
              )
            ret = -1;
#else /* HAVE_LUTIMES || HAVE_UTIMES */
#ifdef HAVE_UTIME
          timep.actime = attrs->atime;
          timep.modtime = attrs->mtime;
          if (utime(name, &timep))
             ret = -1;
#endif /* HAVE_UTIME */
          ret = -1;
#endif /* HAVE_LUTIMES || HAVE_UTIMES */
        }
      
      /* XXX some operation(s) may fail, but that is no excuse to stop
         executing them alltogether. So, we need some system to inform the
         user of the error(s). This is not it. */
      if (ret < 0)
        {
          /* The operation failed. */
          ssh_file_server_send_status(server, id,
                                      ssh_file_server_errno_to_error(errno));
          ssh_xfree(name);
          break;
        }

      /* Free the file name. */
      ssh_xfree(name);

      /* Send success. */
      ssh_file_server_send_status(server, id, SSH_FX_OK);
      break;
      
    case SSH_FXP_FSETSTAT:
      /* Parse the FSETSTAT message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_EXTENDED, ssh_file_attrs_decoder, &attrs,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad FSETSTAT");
          goto return_bad_status;
        }

      /* Look up the handle.  If not found, return error status. */
      handle = ssh_file_server_find_handle(server, value, valuelen);
      if (!handle || handle->is_directory)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      ret = 0;
      if (attrs->flags & SSH_FILEXFER_ATTR_SIZE)
        {
#ifdef HAVE_FTRUNCATE
          if (ftruncate(handle->fd, attrs->size) < 0)
            ret = -1;
#else /* HAVE_FTRUNCATE */
          ssh_warning("ssh_file_server_receive_proc: no ftruncate on this platform");
          ret = -1;
#endif /* HAVE_FTRUNCATE */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
        {
#ifdef HAVE_FCHOWN
          if (fchown(handle->fd, attrs->uid, attrs->gid) < 0)
            ret = -1;
#else /* HAVE_FCHOWN */
          ret = -1;
#endif /* HAVE_FCHOWN */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        {
#ifdef HAVE_FCHMOD
          if (fchmod(handle->fd, attrs->permissions) < 0)
            ret = -1;
#else /* HAVE_FCHMOD */
          ret = -1;
#endif /* HAVE_FCHMOD */
        }
      if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
        {
#ifdef HAVE_FUTIMES
          times[0].tv_sec = attrs->atime;
          times[1].tv_sec = attrs->mtime;
          times[0].tv_usec = times[1].tv_usec = 0L;
          if (futimes(handle->fd, times))
              ret = -1;
#else /* HAVE_FUTIMES */
#ifdef HAVE_UTIME
          timep.actime = attrs->atime;
          timep.modtime = attrs->mtime;
          if(utime(handle->name, &timep))
             ret = -1;
#endif /* HAVE_UTIME */
          ret = -1;
#endif /* HAVE_FUTIMES */
        }

      /* XXX some operation(s) may fail (for example chmod() in BSD fails
         always if not super-user), but that is no excuse to stop executing
         them alltogether. So, we need some system to inform the user of
         the error(s). This is not it. */
      if (ret < 0)
        {
          /* The operation failed. */
          ssh_file_server_send_status(server, id,
                                      ssh_file_server_errno_to_error(errno));
          break;
        }

      /* Send success. */
      ssh_file_server_send_status(server, id, SSH_FX_OK);
      break;

    case SSH_FXP_OPENDIR:
      /* Parse the OPENDIR message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad OPENDIR");
          break;
        }

      /* Open the specified directory. */
      dir = opendir(strlen(name) == 0 ? "." : name);
      
      /* Send error to the client if opening the directory failed. */
      if (!dir)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }

      /* Open was successful.  Wrap the real directory handle to a
         handle object. */
      handle = ssh_file_server_new_handle(server, TRUE, name, (void *)dir);

      /* Free the directory name. */
      ssh_xfree(name);
      
      /* Send a handle message to the client. */
      ssh_file_server_send(server, SSH_FXP_HANDLE,
                           SSH_FORMAT_UINT32, id,
                           SSH_FORMAT_UINT32_STR, handle->value, handle->len,
                           SSH_FORMAT_END);
      break;
      
    case SSH_FXP_READDIR:
      /* Parse the READDIR message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR_NOCOPY, &value, &valuelen,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad READDIR");
          goto return_bad_status;
        }

      /* Look up the handle.  If not found, return error status. */
      handle = ssh_file_server_find_handle(server, value, valuelen);
      if (!handle || !handle->is_directory)
        {
          ssh_file_server_send_status(server, id, SSH_FX_FAILURE);
          break;
        }
      
#ifndef NO_LONG_NAMES
      /* What year is it ? */

      tim = ssh_time();
      ssh_calendar_time(tim, tm, TRUE);
      this_year = tm->year;      
#endif
      
      /* Prepare a buffer for the message. */
      ssh_buffer_init(&buffer);
      for (i = 0; i < 100; i++)
        {
          dp = readdir(handle->dir);
          if (!dp)
            break;
          
#ifndef NO_LONG_NAMES    

          if (handle->name == NULL || strlen(handle->name) == 0)          
            strncpy(long_name, dp->d_name, sizeof(long_name));
          else      
            snprintf(long_name, sizeof(long_name), "%s/%s", 
                     handle->name, dp->d_name);
          
          if (lstat(long_name, &st))
            goto no_long_name;

          /* Fill in the attrs field */
          
          attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
            SSH_FILEXFER_ATTR_PERMISSIONS;
          attrs->size = st.st_size;
          attrs->uid = st.st_uid;
          attrs->gid = st.st_gid;
          attrs->permissions = st.st_mode;
                  
          /* Get user name */
          
#ifdef HAVE_GETPWUID
          if ((pw = getpwuid(st.st_uid)) == NULL)
            snprintf(user_name, sizeof(user_name), "%d", 
                     (int) st.st_uid);
          else
            strncpy(user_name, pw->pw_name, sizeof(user_name));       
#else /* HAVE_GETPWUID */
          snprintf(user_name, sizeof(user_name), "%d", (int) st.st_uid);
#endif /* HAVE_GETPWUID */
          
          /* Get the name of the group */
          
#ifdef HAVE_GETGRGID
          if ((gr = getgrgid(st.st_gid)) == NULL)
            snprintf(group_name, sizeof(group_name), "%d", 
                     (int) st.st_gid);
          else
            strncpy(group_name, gr->gr_name, sizeof(group_name));
#else /* HAVE_GETGRGID */
          snprintf(group_name, sizeof(group_name), "%d", (int) st.st_gid);
#endif /* HAVE_GETGRGID */

          /*
           * tm = localtime(&st.st_mtimespec.tv_sec);
           */
          ssh_calendar_time(st.st_mtime, tm, TRUE);
          
          /* Print time if modified this year, otherwise print year */
          
          if (tm->year == this_year)
            snprintf(date_string, sizeof(date_string),
                     "%3s %2d %2d:%02d",
                     month_name[tm->month % 12], tm->monthday, 
                     tm->hour, tm->minute);
          else
            snprintf(date_string, sizeof(date_string),
                     "%3s %2d  %4d", 
                     month_name[tm->month % 12], tm->monthday, 
                     tm->year);           

          name_ext[0] = '\0';
          if ((st.st_mode & S_IFMT) == S_IFDIR)
            strncpy(name_ext, "/", sizeof(name_ext));
          
          if ((st.st_mode & S_IFMT) == S_IFLNK)
            {
              strncpy(name_ext, " -> ", sizeof(name_ext) - 4);
              if (readlink(long_name, &name_ext[4], 
                           sizeof(name_ext) - 4) == -1)
                strncpy(&name_ext[4], "???", sizeof(name_ext) - 4);
            }
                                
          if ((st.st_mode & S_IFMT) == S_IFREG &&
              (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)
            strncpy(name_ext, "*", sizeof(name_ext));
          /* My NetBSD "ls -l" gives the following format, which I try
           * to duplicate here.
           * 
           * -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer 
           * 1234567890 123 12345678 12345678 12345678 123456789012 */
            
          snprintf(long_name, sizeof(long_name),
                   "%c%c%c%c%c%c%c%c%c%c %3d %-8s %-8s %8lu %12s %s%s",
                   (st.st_mode & S_IFMT) == S_IFREG ? '-' :
                   ((st.st_mode & S_IFMT) == S_IFCHR ? 'c' : 
                    ((st.st_mode & S_IFMT) == S_IFDIR ? 'd' : 
                     ((st.st_mode & S_IFMT) == S_IFBLK ? 'b' :
                      ((st.st_mode & S_IFMT) == S_IFLNK ? 'l' :
#ifdef HAVE_S_IFSOCK
                       ((st.st_mode & S_IFMT) == S_IFSOCK ? 's' :
#endif /* HAVE_S_IFSOCK */
                        ((st.st_mode & S_IFMT) == S_IFIFO ? 'p' :
                         '?')
#ifdef HAVE_S_IFSOCK
                        )
#endif /* HAVE_S_IFSOCK */
                       )))),                
                   st.st_mode & S_IRUSR ? 'r' : '-',
                   st.st_mode & S_IWUSR ? 'w' : '-',
                   st.st_mode & S_ISUID ?                  
                   (st.st_mode & S_IXUSR ? 's' : 'S') :
                   (st.st_mode & S_IXUSR ? 'x' : '-') ,
                   st.st_mode & S_IRGRP ? 'r' : '-',
                   st.st_mode & S_IWGRP ? 'w' : '-',               
                   st.st_mode & S_ISGID ?                   
                   (st.st_mode & S_IXGRP ? 's' : 'S') :
                   (st.st_mode & S_IXGRP ? 'x' : '-'),                      
                   st.st_mode & S_IROTH ? 'r' : '-',
                   st.st_mode & S_IWOTH ? 'w' : '-',
                   st.st_mode & S_IXOTH ? 'x' : '-',               
                   
                   st.st_nlink,
                   user_name,
                   group_name,
                   (unsigned long) st.st_size,
                   date_string,
                   dp->d_name,                             
                   name_ext);
                  
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_UINT32_STR,
                            dp->d_name, strlen(dp->d_name),
                            SSH_FORMAT_UINT32_STR,
                            long_name, strlen(long_name),
                            SSH_FORMAT_EXTENDED, 
                            ssh_file_attrs_encoder, attrs,
                            SSH_FORMAT_END);      
          continue;
          
          /* can't get long name.. settle with the short one */
          
        no_long_name:
       
#endif /* NO_LONG_NAMES */      
            
          /*
           * Long and short names are the same, and the attribute
           * is a dummy one. 
           */
            
          attrs->flags = 0; 
            
          ssh_encode_buffer(&buffer,
                            SSH_FORMAT_UINT32_STR,
                            dp->d_name, strlen(dp->d_name),
                            SSH_FORMAT_UINT32_STR,
                            dp->d_name, strlen(dp->d_name),
                            SSH_FORMAT_EXTENDED, 
                            ssh_file_attrs_encoder, attrs,
                            SSH_FORMAT_END);   
        }

#ifndef NO_LONG_NAMES       
# ifdef HAVE_ENDPWENT
      endpwent();
# endif /* HAVE_ENDPWENT */
# ifdef HAVE_ENDGRENT
      endgrent();
# endif /* HAVE_ENDGRENT */
#endif   
           
      /* If we couldn't read any files, we are at end of directory. */
      if (i == 0)
        ssh_file_server_send_status(server, id, SSH_FX_EOF);
      else
        {
          /* Send the names to the other side. */
          ssh_file_server_send(server, SSH_FXP_NAME,
                               SSH_FORMAT_UINT32, id,
                               SSH_FORMAT_UINT32, (SshUInt32) i,
                               SSH_FORMAT_DATA, ssh_buffer_ptr(&buffer),
                               ssh_buffer_len(&buffer),
                               SSH_FORMAT_END);
        }
      /* Clear the buffer. */
      ssh_buffer_uninit(&buffer);
      break;

    case SSH_FXP_REMOVE:
      /* Parse the REMOVE message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad REMOVE");
          goto return_bad_status;
        }

      /* Remove the file and send response. */
      if (remove(name) < 0)
        ssh_file_server_send_status(server, id,
                                    ssh_file_server_errno_to_error(errno));
      else
        ssh_file_server_send_status(server, id, SSH_FX_OK);

      /* Free the file name. */
      ssh_xfree(name);
      break;
      
    case SSH_FXP_MKDIR:
      /* Parse the MKDIR message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_EXTENDED, ssh_file_attrs_decoder, &attrs,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad MKDIR");
          goto return_bad_status;
        }

      /* Create the directory. */
      if (mkdir(name,
                (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) ?
                attrs->permissions : 0777) < 0)
        ssh_file_server_send_status(server, id,
                                    ssh_file_server_errno_to_error(errno));
      else
        ssh_file_server_send_status(server, id, SSH_FX_OK);

      /* Free the directory name. */
      ssh_xfree(name);
      break;
      
    case SSH_FXP_RMDIR:
      /* Parse the RMDIR message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad RMDIR");
          goto return_bad_status;
        }

      /* Remove the directory and send response. */
      if (rmdir(name) < 0)
        ssh_file_server_send_status(server, id,
                                    ssh_file_server_errno_to_error(errno));
      else
        ssh_file_server_send_status(server, id, SSH_FX_OK);

      /* Free the file name. */
      ssh_xfree(name);
      break;

      
    case SSH_FXP_REALPATH:
      /* Parse the REALPATH message. */
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &id,
                           SSH_FORMAT_UINT32_STR, &name, NULL,
                           SSH_FORMAT_END) != len)
        {
          ssh_warning("ssh_file_server_receive_proc: bad REALPATH");
          goto return_bad_status;
        }
      
      if (ssh_realpath(name, resolved) == NULL)
        ssh_file_server_send_status(server, id, 
                                    ssh_file_server_errno_to_error(errno));
      
      /* Construct a SSH_FXP_NAME consisting only of one name and
         a dummy attributes value */
      
      attrs->flags = 0;                                       
      ssh_file_server_send(server, SSH_FXP_NAME,
                           SSH_FORMAT_UINT32, id,
                           SSH_FORMAT_UINT32, (SshUInt32) 1,
                           SSH_FORMAT_UINT32_STR,
                           resolved, strlen(resolved),
                           SSH_FORMAT_UINT32_STR,
                           resolved, strlen(resolved),
                           SSH_FORMAT_EXTENDED, 
                           ssh_file_attrs_encoder, attrs,
                           SSH_FORMAT_END);      
      ssh_xfree(name);
      break;
      
    default:
      ssh_warning("ssh_file_server_receive_proc: unexpected packet: %d",
                  (int)type);
      break;  
    }

  ssh_xfree(attrs);
  
  /* Check whether further sends are possible, and if not, stop receives
     until we can also send data out. */
  if (!ssh_packet_wrapper_can_send(server->conn))
    ssh_packet_wrapper_can_receive(server->conn, FALSE);
}

/* This callback function is called when EOF is received from the client.
   This causes the server to be destroyed. */

void ssh_file_server_eof_proc(void *context)
{
  SshFileServer server = (SshFileServer)context;
  SshServerHandle handle;

  /* Close and free all file handles. */
  while (server->handles)
    {
      /* Get the first handle on the list. */
      handle = server->handles;

      /* Close the file handle or directory handle. */
      if (handle->is_directory)
        closedir(handle->dir);
      else
        close(handle->fd);

      /* Free the handle.  This also removes it from the list. */
      ssh_file_server_free_handle(server, handle);
    }

  /* Destroy the packet wrapper. */
  ssh_packet_wrapper_destroy(server->conn);

  /* Free the server object. */
  memset(server, 'F', sizeof(*server));
  ssh_xfree(server);
}

/* This callback function is called when can_send has returned FALSE, and
   sending is again possible. */

void ssh_file_server_can_send_proc(void *context)
{
  SshFileServer server = (SshFileServer)context;

  /* Since we can again send packets, we can process more requests.  Thus
     enable receives. */
  ssh_packet_wrapper_can_receive(server->conn, TRUE);
}

/* Wraps the given communications channel into a file transfer server.
   The server is automatically destroyed when the connection is closed. */

SshFileServer ssh_file_server_wrap(SshStream stream)
{
  SshFileServer server;

  /* Allocate a context for the server. */
  server = ssh_xmalloc(sizeof(*server));
  memset(server, 0, sizeof(*server));
  server->handles = NULL;
  server->conn = ssh_packet_wrap(stream,
                                 ssh_file_server_receive_proc,
                                 ssh_file_server_eof_proc,
                                 ssh_file_server_can_send_proc,
                                 (void *)server);
  return server;
}
