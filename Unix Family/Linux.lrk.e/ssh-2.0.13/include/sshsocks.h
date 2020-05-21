/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: libsocks
 *        $Source: /ssh/CVS/src/lib/sshutil/sshsocks.h,v $
 *        $Author: kivinen $
 *
 *        Creation          : 18:09 Nov 10 1996 kivinen
 *        Last Modification : 13:10 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/07/10 13:24:38 $
 *        Revision number   : $Revision: 1.4 $
 *        State             : $State: Exp $
 *        Version           : 1.46
 *
 *        Description       : Socks library
 */
/*
 * $Id: sshsocks.h,v 1.4 1998/07/10 13:24:38 kivinen Exp $
 * $Log: sshsocks.h,v $
 * $EndLog$
 */

#ifndef SSH_SOCKS_H
#define SSH_SOCKS_H

/* SocksInfo command codes (numbers defined in socks protocol) */
typedef enum {
  SSH_SOCKS_COMMAND_CODE_CONNECT = 1,
  SSH_SOCKS_COMMAND_CODE_BIND = 2,
  SSH_SOCKS_COMMAND_CODE_GRANTED = 90,
  SSH_SOCKS_COMMAND_CODE_FAILED_REQUEST = 91,
  SSH_SOCKS_COMMAND_CODE_FAILED_IDENTD = 92,
  SSH_SOCKS_COMMAND_CODE_FAILED_USERNAME = 93
} SocksCommandCode;

/* SocksInfo structure. */
typedef struct SocksInfoRec {
  unsigned int socks_version_number; /* Socks version number, should be 4 */
  SocksCommandCode command_code; /* Socks command code, see above */
  char *ip;			/* Ip number (as string) */
  char *port;			/* Port number (as string) */
  char *username;		/* Username (as string) */
} *SocksInfo;

typedef enum {
  SSH_SOCKS_SUCCESS = 0,	/* Everything ok */
  SSH_SOCKS_TRY_AGAIN,		/* Not enough data, read more data and call
				   this function again later. */
  SSH_SOCKS_FAILED_REQUEST,	/* Request rejected or failed */
  SSH_SOCKS_FAILED_IDENTD,	/* Request rejected because socks server
				   cannot connect to identd on the client */
  SSH_SOCKS_FAILED_USERNAME,	/* Request rejected because identd and
				   request reported different usernames */
  SSH_SOCKS_ERROR_PROTOCOL_ERROR,
				/* Socks protocol error */
  SSH_SOCKS_ERROR_INVALID_ARGUMENT,
				/* Invalid arguments to call */
  SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION
				/* Unsupported socks version */

} SocksError;

/*
 * Free SocksInfo structure (all fields, and the structure itself).
 * Sets the pointer to socksinfo structure to NULL (NOTE this takes
 * pointer to socksinfo pointer for this purpose). 
 */
void ssh_socks_free(SocksInfo *socksinfo);

/* Server functions */
/*
 * Parse incoming socks connection from buffer. Consume the request packet data
 * from buffer. If everything is ok it allocates SocksInfo strcture and store
 * the request fields in it (sets socks_version_number, command_code, ip, port,
 * username). Returns SSH_SOCKS_SUCCESS, SSH_SOCKS_TRY_AGAIN, or
 * SSH_SOCKS_ERROR_*. If anything other than SSH_SOCKS_SUCCESS is returned the
 * socksinfo is set to NULL.
 * Use ssh_socks_free to free socksinfo data.
 */
SocksError ssh_socks_server_parse_open(SshBuffer *buffer,
				       SocksInfo *socksinfo);

/*
 * Make socks reply packet that can be sent to client and store it to buffer.
 * If connection is granted set command_code to SSH_SOCKS_COMMAND_CODE_GRANTED,
 * otherwise set it to some error code (SSH_SOCKS_COMMAND_CODE_FAILED_*).
 * The port and ip from the socksinfo are sent along with reply and if
 * the request that was granted was bind they should indicate the port and ip
 * address of the other end of the socket. 
 * Does NOT free the SocksInfo structure.
 */
SocksError ssh_socks_server_generate_reply(SshBuffer *buffer,
					   SocksInfo socksinfo);

/* Client functions */
/*
 * Make socks connect or bind request and store it to buffer.
 * Uses all fields in socksinfo structure. Returns SSH_SOCKS_SUCCESS, or
 * SSH_SOCKS_ERROR. Command_code must be either SSH_SOCKS_COMMAND_CODE_BIND,
 * or SSH_SOCKS_COMMAND_CODE_CONNECT. 
 * Does NOT free the SocksInfo structure.
 */
SocksError ssh_socks_client_generate_open(SshBuffer *buffer,
					  SocksInfo socksinfo);

/*
 * Parse socks reply packet. Consume the reply packet data from buffer.
 * If the request was not granted (returns SSH_SOCKS_FAILED_*) the socket can
 * be immediately closed down (there will not be any additional data from the
 * socks server.
 * If the request is granted allocate socksinfo structure and store information
 * from request packet to there (sets socks_version_number, command_code, ip,
 * and port fields).
 * Use ssh_socks_free to free socksinfo data. If socksinfo pointer is NULL
 * then it is ignored. 
 */
SocksError ssh_socks_client_parse_reply(SshBuffer *buffer,
					SocksInfo *socksinfo);

#endif /* SSH_SOCKS_H */
