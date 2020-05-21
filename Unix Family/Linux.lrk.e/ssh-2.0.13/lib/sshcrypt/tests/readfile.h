/*

  readfile.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Mar 27 19:46:56 1997 [mkojo]

  Reading test cases...

  */

/*
 * $Id: readfile.h,v 1.4 1998/05/26 20:32:25 mkojo Exp $
 * $Log: readfile.h,v $
 * $EndLog$
 */

#ifndef READFILE_H
#define READFILE_H

#define BUFFER_SIZE 1024

typedef enum
{
  RF_EMPTY           = -10,
  RF_CORRUPTED       = -2,
  RF_NOT_INITIALIZED = -1,
  RF_FAILED          = 0,
  RF_HEX             = 1,
  RF_ASCII           = 2,
  RF_LABEL           = 100,
  RF_COMMENT         = 200,
  RF_LINEFEED        = 201,
  RF_WRITE           = 1024,
  RF_READ            = 1025
} RFStatus;

/* Initialize the internal file context. */

RFStatus ssh_t_read_init(const char *file);

RFStatus ssh_t_write_init(const char *file);

void ssh_t_close();

/* Read next token from the file. Giving buf pointing to a static buffer. */

RFStatus ssh_t_read_token(unsigned char **buf, size_t *len);

/* Write buf as type to a file. */

void ssh_t_write_token(RFStatus type, unsigned char *buf, size_t len);

#endif /* READFILE_H */
