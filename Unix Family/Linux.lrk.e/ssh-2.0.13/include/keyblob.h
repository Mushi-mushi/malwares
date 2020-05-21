/*

  keyblob.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Dec  9 23:43:39 1996 [mkojo]

  Handling the key blob.

  */

/*
 * $Id: keyblob.h,v 1.6 1999/01/21 12:38:22 tri Exp $
 * $Log: keyblob.h,v $
 * $EndLog$
 */

#ifndef KEYBLOB_H
#define KEYBLOB_H

/*
 * NOTE: Version number must be in major.minor format, NO letters etc allowed!
 */
#define SSH_BLOB_VERSION "2.1"

/*
 * Read key blob from string buffer (null terminated) and convert it to
 * binary format. Returns xmallocated blob, and if blob_len, version_major,
 * version_minor, or is_public have non NULL value the length of blob,
 * major and minor version numbers of format, and whatever the blob was
 * private or public key are returned.
 */
unsigned char *ssh_key_blob_read_from_string(const char *str,
                                             size_t *blob_len,
                                             char **headers,
                                             unsigned int *version_major,
                                             unsigned int *version_minor,
                                             Boolean *is_public);

/*
 * Read key blob from file and convert it to binary format. Returns
 * xmallocated blob and its length. If blob_len ptr is NULL it isn't returned.
 */
unsigned char *ssh_key_blob_read(FILE *fp, size_t *blob_len, char **comments);

/*
 * Write blob to buffer as ascii string. Take initialized buffer and appends
 * blob there.
 */
void ssh_key_blob_write_to_buffer(SshBuffer *buffer,
                                  unsigned char *blob,
                                  size_t blob_len,
                                  const char *comments,
                                  Boolean is_public);

/*
 * Write blob to file as ascii string. 
 */
void ssh_key_blob_write(FILE *fp, unsigned char *blob, size_t blob_len,
                        const char *comments, Boolean is_public);

#endif /* KEYBLOB_H */
