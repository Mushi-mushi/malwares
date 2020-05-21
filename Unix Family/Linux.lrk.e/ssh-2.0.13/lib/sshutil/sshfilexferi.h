/*

sshfilexferi.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Internal definitions for the SSH file transfer protocol.

Protocol:

  ATTRS:
    uint32   flags
    uint32   size_high    present only if flag 0x01
    uint32   size_low     --''----
    uint32   uid          present only if flag 0x02
    uint32   gid          --''----
    uint32   permissions  present only if flag 0x04

  client:
    SSH_FXP_INIT  -> VERSION
      uint32   version
  server:
    SSH_FXP_VERSION
      uint32   version

  client:
    SSH_FXP_OPEN -> STATUS / HANDLE
      uint32   id
      string   name
      uint32   flags  - note: portable version, defined below
      ATTRS    attrs
    SSH_FXP_CLOSE -> STATUS
      uint32   id
      string   handle
    SSH_FXP_READ -> STATUS / DATA
      uint32   id
      uint32   offset_high
      uint32   offset_low
      uint32   len
    SSH_FXP_WRITE -> STATUS
      uint32   id
      uint32   offset_high
      uint32   offset_low
      string   data
    SSH_FXP_LSTAT -> STATUS / ATTRS
      uint32   id
      string   name
    SSH_FXP_FSTAT -> STATUS / ATTRS
      uint32   id
      string   handle
    SSH_FXP_SETSTAT -> STATUS
      uint32   id
      string   name
      ATTRS    attrs
    SSH_FXP_FSETSTAT -> STATUS
      uint32   id
      string   handle
      ATTRS    attrs
    SSH_FXP_OPENDIR -> STATUS / HANDLE
      uint32   id
      string   path
    SSH_FXP_READDIR -> STATUS / NAME
      uint32   id
      string   handle
    SSH_FXP_REMOVE -> STATUS
      uint32   id
      string   name
    SSH_FXP_MKDIR -> STATUS
      uint32   id
      string   name
      ATTRS    attrs
    SSH_FXP_RMDIR -> STATUS
      uint32   id
      string   name
    SSH_FXP_REALPATH -> STATUS / NAME
      uint32   id
      string   name
    SSH_FXP_STAT -> STATUS / ATTRS
      uint32   id
      string   name
   
  server:
    SSH_FXP_STATUS
      uint32   id
      uint32   error
    SSH_FXP_HANDLE
      uint32   id
      string   handle
    SSH_FXP_DATA
      uint32   id
      string   data
    SSH_FXP_NAME
      uint32   id
      uint32   count
      [ repeated count times: ]
        string   name  
        string   long_name
        ATTRS    attrs
    SSH_FXP_ATTRS
      uint32   id
      ATTRS    attrs
      
*/

#ifndef SSHFILEXFERI_H
#define SSHFILEXFERI_H


/* Current protocol version. */
#define SSH_FILEXFER_VERSION    0

/* Packet types. */
#define SSH_FXP_INIT            1
#define SSH_FXP_VERSION         2
#define SSH_FXP_OPEN            3
#define SSH_FXP_CLOSE           4
#define SSH_FXP_READ            5
#define SSH_FXP_WRITE           6
#define SSH_FXP_LSTAT           7
#define SSH_FXP_FSTAT           8
#define SSH_FXP_SETSTAT         9
#define SSH_FXP_FSETSTAT       10
#define SSH_FXP_OPENDIR        11
#define SSH_FXP_READDIR        12
#define SSH_FXP_REMOVE         13
#define SSH_FXP_MKDIR          14
#define SSH_FXP_RMDIR          15
#define SSH_FXP_REALPATH       16
#define SSH_FXP_STAT           17
#define SSH_FXP_STATUS         101
#define SSH_FXP_HANDLE         102
#define SSH_FXP_DATA           103
#define SSH_FXP_NAME           104
#define SSH_FXP_ATTRS          105

/* Portable versions of O_RDONLY etc. */
#define SSH_FXF_READ            0x0001
#define SSH_FXF_WRITE           0x0002
#define SSH_FXF_APPEND          0x0004
#define SSH_FXF_CREAT           0x0008
#define SSH_FXF_TRUNC           0x0010
#define SSH_FXF_EXCL            0x0020

/* Encodes a SshFileAttributes object supplied as the next argument.
   The next argument should be of type SshFileAttributes. */
void ssh_file_attrs_encoder(SshBuffer *buffer, va_list *app);

/* Decodes a SshFileAttributes object.  The next argument should be of type
   SshFileAttributes *.  This allocates an attributes object and copies data
   to it. */
size_t ssh_file_attrs_decoder(const unsigned char *buf, size_t len,
                              va_list *app);

#endif /* SSHFILEXFERI_H */
