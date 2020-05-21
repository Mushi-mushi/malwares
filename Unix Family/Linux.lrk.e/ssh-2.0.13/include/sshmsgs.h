/*

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Antti Huima <huima@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

/*
 * $Id: sshmsgs.h,v 1.16 1998/07/11 12:37:05 tri Exp $
 * $Log: sshmsgs.h,v $
 * $EndLog$
 */

#ifndef SSHMSGS_H
#define SSHMSGS_H

/* Maximum length of packet payload, including packet type. */
#define SSH_MAX_PAYLOAD_LENGTH		32768

/* Packet numbers for the SSH transport layer protocol. */
#define SSH_MSG_DISCONNECT             1
#define SSH_MSG_IGNORE                 2
#define SSH_MSG_UNIMPLEMENTED          3
#define SSH_MSG_DEBUG		       4
#define SSH_MSG_SERVICE_REQUEST        5
#define SSH_MSG_SERVICE_ACCEPT         6

#define SSH_MSG_KEXINIT               20
#define SSH_MSG_NEWKEYS               21



/* Numbers 15-19 for KEX packets.  Different KEX methods may reuse
   message numbers in this range. */
#define SSH_FIRST_KEX_PACKET	      30

/* Double encrypting key exchange */

#define SSH_MSG_KEXDE_HOSTKEY         30
#define SSH_MSG_KEXDE_SESSIONKEY      31

/* Diffie-Hellman key exchange */

#define SSH_MSG_KEXDH_INIT            30
#define SSH_MSG_KEXDH_REPLY           31


#define SSH_FIRST_SERVICE_PACKET      50


/* Packet numbers for the SSH userauth protocol. */
#define SSH_FIRST_USERAUTH_PACKET     50
#define SSH_MSG_USERAUTH_REQUEST      50
#define SSH_MSG_USERAUTH_FAILURE      51
#define SSH_MSG_USERAUTH_SUCCESS      52
#define SSH_MSG_USERAUTH_BANNER       53

#define SSH_FIRST_USERAUTH_METHOD_PACKET  60
#define SSH_LAST_USERAUTH_METHOD_PACKET   79
#define SSH_LAST_USERAUTH_PACKET      79

/* Packet numbers for various authentication methods. */

/* Password authentication */
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ	60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREPLY	61

/* Challenge-response authentication */
#define SSH_MSG_USERAUTH_CHALLENGE		60

/* SecurID authentication */
#define SSH_MSG_USERAUTH_SECURID_PINREQ		60
#define SSH_MSG_USERAUTH_SECURID_PINREPLY	61

/* Public key authentication */
#define SSH_MSG_USERAUTH_PK_OK                  60

/* #define SSH_FIRST_USERAUTH_SERVICE_PACKET  30 */

/* Packet numbers for the SSH connection protocol. */
#define SSH_MSG_GLOBAL_REQUEST                  80
#define SSH_MSG_REQUEST_SUCCESS                 81
#define SSH_MSG_REQUEST_FAILURE                 82
#define SSH_MSG_CHANNEL_OPEN                    90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93
#define SSH_MSG_CHANNEL_DATA                    94
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95
#define SSH_MSG_CHANNEL_EOF                     96
#define SSH_MSG_CHANNEL_CLOSE                   97
#define SSH_MSG_CHANNEL_REQUEST                 98
#define SSH_MSG_CHANNEL_SUCCESS                 99
#define SSH_MSG_CHANNEL_FAILURE                 100

#define SSH_MSG_RESERVED                        255

/* Debug message types */
#define SSH_DEBUG_DEBUG		      0
#define SSH_DEBUG_DISPLAY	      1

/* Disconnection reasons */

#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      1
#define SSH_DISCONNECT_PROTOCOL_ERROR                   2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED              3
#define SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED       4
#define SSH_DISCONNECT_MAC_ERROR                        5
#define SSH_DISCONNECT_COMPRESSION_ERROR                6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE   	9
#define SSH_DISCONNECT_CONNECTION_LOST		       10
#define SSH_DISCONNECT_BY_APPLICATION		       11
#define SSH_DISCONNECT_AUTHENTICATION_ERROR	       12

/* Extended channel data types. */

#define SSH_EXTENDED_DATA_STDERR		1

/* Channel open result codes. */

#define SSH_OPEN_OK				0
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED	1
#define SSH_OPEN_CONNECT_FAILED			2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE		3
#define SSH_OPEN_RESOURCE_SHORTAGE		4

#endif /* SSHMSGS_H */
