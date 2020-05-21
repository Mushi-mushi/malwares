/*

sshfilexfer.h

Author: Sami Lehtinen <sjl@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

sshfilexfer-stuff, that is common to both server and client.

 */
#include "sshincludes.h"
#include "sshfilexfer.h"

/* Duplicate a SshFileAttributes-structure.
 */
SshFileAttributes ssh_file_attributes_dup(SshFileAttributes attributes)
{
  SshFileAttributes copy;

  if (attributes == NULL)
    return NULL;
  
  copy = ssh_xcalloc(1, sizeof(struct SshFileAttributesRec));
  
  copy->flags = attributes->flags;
  copy->size = attributes->size;
  copy->uid = attributes->uid;
  copy->gid = attributes->gid;
  copy->mtime = attributes->mtime;
  copy->atime = attributes->atime;
  copy->permissions = attributes->permissions;

  return copy;  
}

