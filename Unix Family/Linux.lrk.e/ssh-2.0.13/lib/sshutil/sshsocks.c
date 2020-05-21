/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: libsocks
 *        $Source: /ssh/CVS/src/lib/sshutil/sshsocks.c,v $
 *        $Author: tmo $
 *
 *        Creation          : 18:09 Nov 10 1996 kivinen
 *        Last Modification : 13:35 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/09/23 11:15:00 $
 *        Revision number   : $Revision: 1.8 $
 *        State             : $State: Exp $
 *        Version           : 1.66
 *
 *        Description       : Socks library
 */
/*
 * $Id: sshsocks.c,v 1.8 1998/09/23 11:15:00 tmo Exp $
 * $Log: sshsocks.c,v $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshmalloc.h"
#include "sshsocks.h"

#define SOCKS_REPLY_SIZE	8
#define SOCKS_COMMAND_SIZE	8
#define SOCKS_MAX_NAME_LEN	128

#define SOCKS_SMALL_BUFFER	64 /* enough to have ip-number as string */

/*
 * Free SocksInfo structure (all fields, and the structure itself).
 * Sets the pointer to socksinfo structure to NULL (NOTE this takes
 * pointer to socksinfo pointer for this purpose). 
 */
void ssh_socks_free(SocksInfo *socksinfo)
{
  if (socksinfo == NULL)
    {
      ssh_fatal("ssh_socks_free: socksinfo == NULL");
    }
  if (*socksinfo == NULL)
    {
      ssh_fatal("ssh_socks_free: *socksinfo == NULL");
    }
  if ((*socksinfo)->ip != NULL)
    ssh_xfree((*socksinfo)->ip);
  (*socksinfo)->ip = NULL;
  
  if ((*socksinfo)->port != NULL)
    ssh_xfree((*socksinfo)->port);
  (*socksinfo)->port = NULL;
  
  if ((*socksinfo)->username != NULL)
    ssh_xfree((*socksinfo)->username);
  (*socksinfo)->username = NULL;

  ssh_xfree(*socksinfo);
  *socksinfo = NULL;
}

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
SocksError ssh_socks_server_parse_open(SshBuffer *buffer, SocksInfo *socksinfo)
{
  unsigned char *data, buf[SOCKS_SMALL_BUFFER];
  unsigned long len, i, port;

  *socksinfo = NULL;
  len = ssh_buffer_len(buffer);
  data = ssh_buffer_ptr(buffer);
  
  /* Check if enough data for header and name */
  if (len < SOCKS_COMMAND_SIZE + 1)
    {
      return SSH_SOCKS_TRY_AGAIN;
    }

  /* Find the end of username */
  for(i = SOCKS_COMMAND_SIZE; i < len; i++)
    {
      if (data[i] == '\0')
	break;
    }

  /* End of username not found, return either error or try_again */
  if (i == len || data[i] != '\0')
    {
      if (len > SOCKS_COMMAND_SIZE + SOCKS_MAX_NAME_LEN)
	{
	  return SSH_SOCKS_ERROR_PROTOCOL_ERROR;
	}
      return SSH_SOCKS_TRY_AGAIN;
    }

  if (data[0] != 4)
    {
      return SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION;
    }
  *socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
  memset(*socksinfo, 0, sizeof(struct SocksInfoRec));
  
  (*socksinfo)->socks_version_number = data[0];
  (*socksinfo)->command_code = data[1];
  
  port = (((unsigned long) data[2]) << 8) | ((unsigned long) data[3]);
  snprintf((char *) buf, SOCKS_SMALL_BUFFER, "%lu", port);
  (*socksinfo)->port = ssh_xmalloc(strlen((char *) buf) + 1);
  strcpy((*socksinfo)->port, (char *) buf);

  snprintf((char *) buf, SOCKS_SMALL_BUFFER, "%lu.%lu.%lu.%lu",
	   (unsigned long) data[4], (unsigned long) data[5],
	   (unsigned long) data[6], (unsigned long) data[7]);
  (*socksinfo)->ip = ssh_xmalloc(strlen((char *) buf) + 1);
  strcpy((*socksinfo)->ip, (char *) buf);

  (*socksinfo)->username = ssh_xmalloc(strlen((char *) data +
					      SOCKS_COMMAND_SIZE) + 1);
  strcpy((*socksinfo)->username, (char *) data + SOCKS_COMMAND_SIZE);
  ssh_buffer_consume(buffer, SOCKS_COMMAND_SIZE +
		     strlen((char *) data + SOCKS_COMMAND_SIZE) + 1);
  return SSH_SOCKS_SUCCESS;
}

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
					   SocksInfo socksinfo)
{
  unsigned char *data, *endp, *p;
  unsigned long port, ip;
  
  if (socksinfo == NULL)
    {
      ssh_fatal("ssh_socks_server_genrerate_reply: socksinfo == NULL");
    }
  if (socksinfo->socks_version_number != 0)
    {
      return SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION;
    }
  if (socksinfo->command_code < SSH_SOCKS_COMMAND_CODE_GRANTED)
    {
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  port = strtol(socksinfo->port, (char **)&endp, 0);
  if (port >= 65536 || *endp != '\0' ||
      endp == (unsigned char *) socksinfo->port)
    {
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  ssh_buffer_append_space(buffer, &data, SOCKS_REPLY_SIZE);
  *data++ = socksinfo->socks_version_number;
  *data++ = socksinfo->command_code;
  *data++ = (unsigned char)((port & 0xff00U) >> 8);
  *data++ = (unsigned char)(port & 0xffU);

  p = (unsigned char *) socksinfo->ip;
  
  /* 1 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_REPLY_SIZE);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 2 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_REPLY_SIZE);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 3 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_REPLY_SIZE);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 4 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || (*endp != ',' && *endp != '\0') || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_REPLY_SIZE);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  return SSH_SOCKS_SUCCESS;
}

/* Client functions */
/*
 * Make socks connect or bind request and store it to buffer.
 * Uses all fields in socksinfo structure. Returns SSH_SOCKS_SUCCESS, or
 * SSH_SOCKS_ERROR. Command_code must be either SSH_SOCKS_COMMAND_CODE_BIND,
 * or SSH_SOCKS_COMMAND_CODE_CONNECT. 
 * Does NOT free the SocksInfo structure.
 */
SocksError ssh_socks_client_generate_open(SshBuffer *buffer,
					  SocksInfo socksinfo)
{
  unsigned char *data, *endp, *p;
  const char *username;
  unsigned long port, ip;
  
  if (socksinfo == NULL)
    {
      ssh_fatal("ssh_socks_server_genrerate_reply: socksinfo == NULL");
    }
  if (socksinfo->socks_version_number != 4)
    {
      return SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION;
    }
  if (socksinfo->command_code >= SSH_SOCKS_COMMAND_CODE_GRANTED)
    {
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  port = strtol(socksinfo->port, (char **)&endp, 0);
  if (port >= 65536 || *endp != '\0' ||
      endp == (unsigned char *) socksinfo->port)
    {
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  
  if (socksinfo->username == NULL)
    username = "";
  else
    username = socksinfo->username;

  if (strlen(username) > SOCKS_MAX_NAME_LEN)
    {
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  
  ssh_buffer_append_space(buffer, &data, SOCKS_COMMAND_SIZE +
		      strlen(username) + 1);
  *data++ = socksinfo->socks_version_number;
  *data++ = socksinfo->command_code;
  *data++ = (unsigned char)((port & 0xff00U) >> 8);
  *data++ = (unsigned char)(port & 0xffU);
  
  p = (unsigned char *) socksinfo->ip;
  
  /* 1 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_COMMAND_SIZE +
			     strlen(username) + 1);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 2 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_COMMAND_SIZE +
			     strlen(username) + 1);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 3 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || *endp != '.' || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_COMMAND_SIZE +
			     strlen(username) + 1);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;
  p = endp + 1;

  /* 4 */
  ip = strtol((char *) p, (char **)&endp, 0);
  if (p == endp || (*endp != ',' && *endp != '\0') || ip >= 256)
    {
      ssh_buffer_consume_end(buffer, SOCKS_COMMAND_SIZE +
			     strlen(username) + 1);
      return SSH_SOCKS_ERROR_INVALID_ARGUMENT;
    }
  *data++ = (unsigned char)ip;

  strcpy((char *) data, username);
  return SSH_SOCKS_SUCCESS;
}

/*
 * Parse socks reply packet. Consume the reply packet data from buffer.
 * If the request was not granted (returns SSH_SOCKS_FAILED_*) the socket can
 * be immediately closed down (there will not be any additional data from the
 * socks server.
 * If the request is granted allocate socksinfo structure and store information
 * from request packet to there (sets socks_version_number, command_code, ip,
 * and port fields).
 * Use ssh_socks_free to free socksinfo data.
 */
SocksError ssh_socks_client_parse_reply(SshBuffer *buffer,
					SocksInfo *socksinfo)
{
  unsigned char *data, buf[SOCKS_SMALL_BUFFER];
  unsigned long len, port;

  if (socksinfo)
    *socksinfo = NULL;
  len = ssh_buffer_len(buffer);
  data = ssh_buffer_ptr(buffer);
  
  /* Check if enough data for header and name */
  if (len < SOCKS_REPLY_SIZE)
    {
      return SSH_SOCKS_TRY_AGAIN;
    }

  if (data[0] != 0)
    {
      return SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION;
    }
  if (data[1] != SSH_SOCKS_COMMAND_CODE_GRANTED)
    {
      switch (data[1])
	{
	case SSH_SOCKS_COMMAND_CODE_FAILED_REQUEST:
	  return SSH_SOCKS_FAILED_REQUEST;
	case SSH_SOCKS_COMMAND_CODE_FAILED_IDENTD:
	  return SSH_SOCKS_FAILED_IDENTD;
	case SSH_SOCKS_COMMAND_CODE_FAILED_USERNAME:
	  return SSH_SOCKS_FAILED_USERNAME;
	default:
	  return SSH_SOCKS_ERROR_PROTOCOL_ERROR;
	}
    }
  if (socksinfo)
    {
      *socksinfo = ssh_xmalloc(sizeof(struct SocksInfoRec));
      memset(*socksinfo, 0, sizeof(struct SocksInfoRec));

      (*socksinfo)->socks_version_number = data[0];
      (*socksinfo)->command_code = data[1];

      port = (((unsigned long) data[2]) << 8) | ((unsigned long) data[3]);
      snprintf((char *) buf, SOCKS_SMALL_BUFFER, "%lu", port);
      (*socksinfo)->port = ssh_xmalloc(strlen((char *) buf) + 1);
      strcpy((*socksinfo)->port, (char *) buf);

      snprintf((char *) buf, SOCKS_SMALL_BUFFER, "%lu.%lu.%lu.%lu",
	       (unsigned long) data[4], (unsigned long) data[5],
	       (unsigned long) data[6], (unsigned long) data[7]);
      (*socksinfo)->ip = ssh_xmalloc(strlen((char *) buf) + 1);
      strcpy((*socksinfo)->ip, (char *) buf);

      (*socksinfo)->username = NULL;
    }
  ssh_buffer_consume(buffer, SOCKS_REPLY_SIZE);
  return SSH_SOCKS_SUCCESS;
}
