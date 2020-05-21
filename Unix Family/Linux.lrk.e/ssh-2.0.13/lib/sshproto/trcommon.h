/*

trcommon.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Common (client+server) internal definitions for the transport layer protocol.

*/

/*
 * $Id: trcommon.h,v 1.22 1999/04/29 13:38:42 huima Exp $
 * $Log: trcommon.h,v $
 * $EndLog$
 */

#ifndef TRCOMMON_H
#define TRCOMMON_H

#include "sshtrans.h"
#include "sshcrypt.h"
#include "sshstream.h"
#include "sshbuffer.h"
#include "bufzip.h"
#include "sshmp.h" /* was "gmp.h" */

#define SSH_VERSION_STRING              "SSH-2.0-%.200s"
#define SSH_VERSION_STRING_COMPAT       "SSH-1.99-%.200s"

#define SSH_MAX_TOTAL_PACKET_LENGTH     35000
#define SSH_MAX_PAYLOAD_LENGTH          32768
#define SSH_CONTROL_RESERVE             5000  /* reserve for control packets */
#define SSH_BUFFERING_LIMIT             50000

typedef enum
{
  SENT_NOTHING,
  SENT_VERSION,
  SENT_KEXINIT,
  SENT_KEX1_FINAL,
  SENT_NEWKEYS,
  SENT_SERVICE_REQUEST,
  SENT_INTERACTIVE,
  SENT_DEAD
} SshSentState;

typedef enum
{
  RECEIVED_NOTHING,
  RECEIVED_VERSION,
  RECEIVED_KEXINIT,
  RECEIVED_KEX1_IGNORED,
  RECEIVED_KEX1_FINAL,
  RECEIVED_KEY_CHECK,
  RECEIVED_KEX2,
  RECEIVED_NEWKEYS,
  RECEIVED_SERVICE_REQUEST,
  RECEIVED_INTERACTIVE,
  RECEIVED_DEAD
} SshReceivedState;

typedef const struct SshKexTypeRec *SshKexType;

typedef struct
{
  /* General state information. */
  Boolean server;                   /* Are we running as server? */
  Boolean version_compatibility;    /* Support compatibility with old ssh. */
  Boolean doing_rekey;              /* Are we doing rekey? */
  Boolean rekey_request_sent;       /* Have we sent rekey request. */
  Boolean destroy_after_disconnect; /* Destroy this context after disconnect */
  Boolean read_has_blocked;         /* We are not receiving read callbacks. */
  SshSentState sent_state;          /* Send state. */
  SshReceivedState received_state;  /* Receive state. */
  SshStream connection;             /* Connection to other side. */
  SshRandomState random_state;      /* Random state to use. */
  SshTransportParams params;        /* Configuration parameters. */

  /* Packet sequence numbers. */
  unsigned long incoming_sequence_number;
  unsigned long outgoing_sequence_number;
  
  /* State for data going out to the connection. */
  SshBuffer outgoing;               /* Pending outgoing data. */
  Boolean outgoing_eof;             /* Send EOF when buffer empty. */

  /* State for packets coming from the connection. */
  SshBuffer *incoming_packet;       /* Received packet. */
  size_t incoming_packet_index;     /* How much data has been received? */
  size_t incoming_packet_len;       /* Total length of incoming packet. */

  /* State for data going upwards. */
  SshStream up_stream;              /* The upward stream (ourself). */
  SshStreamCallback up_callback;    /* The application callback. */
  void *up_context;                 /* The application context. */
  SshBuffer up_outgoing;            /* Pending outgoing data upwards. */
  Boolean up_outgoing_eof;          /* Send EOF after current data. */
  SshBuffer up_incoming;            /* SshBuffer for incoming packets.*/
  Boolean up_write_blocked;         /* Write from up has failed. */
  Boolean up_read_blocked;          /* Read from up has failed. */
  
  /* Data for processing version number. */
  char *own_version;                /* Does not include crlf. */
  char remote_version[256];         /* Will not include crlf. */
  size_t remote_version_index;

  /* Version callback.  This is called when remote version string has been
     received. */
  SshVersionCallback version_callback;
  void *version_context;
  
  /* Guessed algorithms. */
  char *guessed_kex;
  char *guessed_host_key;
  
  /* Current selected algorithms (names).  The ciphers/macs are not actually
     taken into use (the objects below updated) until NEWKEYS is sent or
     received. */
  char *kex_name;
  char *host_key_name;  /* Negotiated `default' public key algorithm */
  char *host_key_names; /* List of common host key algorithms */
  struct SideKexInfo {
    char *cipher_name;
    char *mac_name;
    char *compression_name;
    unsigned char encryption_key[32];
    unsigned char iv[32];
    unsigned char integrity_key[32];
  } c_to_s, s_to_c;

  /* Internal objects for the algorithms currently in use. */
  SshKexType kex;                   /* Note: statically allocated, const. */
  SshHash hash;                     /* The hash algorithm is implied by
                                     * the key exchange algorithm. */
  SshCipher outgoing_cipher;
  size_t incoming_granularity;
  SshCipher incoming_cipher;
  size_t outgoing_granularity;
  SshMac outgoing_mac;
  SshMac incoming_mac;

  /* Compression streams for both incoming and outgoing data. */
  SshCompression compression_outgoing;
  SshCompression compression_incoming;
  
  /* Shared buffer for all types of compression.  This is always allocated,
     even if no compression is in use. */
  SshBuffer *compression_buffer;

  /* Statistics for compression. */
  /* XXX need 64 bit its here! */
  unsigned long compressed_incoming_bytes;
  unsigned long uncompressed_incoming_bytes;
  unsigned long compressed_outgoing_bytes;
  unsigned long uncompressed_outgoing_bytes;
  
  /* Copies of key exchange packets.  These are used in computing the session
     identifier (which, in turn, is used to check the integrity of the
     key exchange). */
  SshBuffer *client_kexinit_packet;
  SshBuffer *server_kexinit_packet;
  SshBuffer *client_kex1_packet;
  SshBuffer *server_kex1_packet;

  /* The unique session identifier for this session.  This is not changed
     even if keys are re-exchanged. */
  unsigned char session_identifier[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t session_identifier_len;

  /* This is the validation hash computed from this particular key exchange.
     In the first exchange, this is the same as the session identifier. */
  unsigned char exchange_hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t exchange_hash_len;

  /* Service name.  The name to send for client, the received name for
     server. */
  char *service_name;

  /* This is used by both server and client. */
  SshBuffer *public_host_key_blob;
  
  /* For client only. */
  SshPublicKey public_host_key;
  SshPublicKey public_server_key;
  char *server_host_name;
  SshKeyCheckCallback key_check;
  void *key_check_context;
  Boolean key_check_returned;
  Boolean key_check_result;
  void *key_check_callback_context;
  
  /* For server only. */
  SshPrivateKey private_host_key;
  SshPrivateKey private_server_key;
  SshBuffer *public_server_key_blob;

  /* For dh methods: the group, "secret" and the exchange buffer */

  SshIntC dh_p;
  SshIntC dh_g;
  SshIntC dh_e;
  SshIntC dh_f;
  SshIntC dh_k;
  SshIntC dh_secret;

  /* Compatibility with older ssh-2 versions.  Variables in this section
     are set to defaults in ssh_tr_create and filled in properly in
     ssh_tr_input_version. */

  /* MAC-bug, which is in versions ssh-2.0.9 and earlier (here our
     implementation was conflicting with the draft) */
  Boolean ssh_old_mac_bug_compat;

  /* Key generation bug, which is in versions ssh-2.0.10 and earlier. */
  Boolean ssh_old_keygen_bug_compat;

  /* Draft incompatibility bug in publickey authentication, which is
     in versions ssh-2.0.12 and earlier. */
  Boolean ssh_old_publickey_bug_compat;
  
} *SshTransportCommon;


/* Creates the SshTransportCommon object, and performs initializations that
   are common to client and server.  Initialization should continue with
   client or server specific initializations, and finally a call to
   ssh_tr_create_final. */
SshTransportCommon ssh_tr_create(SshStream connection, Boolean server,
                                 Boolean compatibility,
                                 Boolean fake_old_version,
                                 const char *application_version,
                                 SshRandomState random_state,
                                 SshTransportParams params);

/* Prepares the client side for key exchange. */
void ssh_tr_client_init_kex(SshTransportCommon tr,
                            const char *service_name,
                            const char *server_host_name,
                            SshKeyCheckCallback key_check,
                            void *key_check_context);

/* Prepares the server side for key exchange. */
void ssh_tr_server_init_kex(SshTransportCommon tr,
                            SshPrivateKey private_host_key,
                            SshPrivateKey private_server_key,
                            const unsigned char *public_host_key_blob,
                            size_t public_host_key_blob_len);

/* Finalizes the creation of the transport layer protocol.  Wraps it into
   a stream, and returns the stream.  The lower-level object should not
   be accessed after this call; the object will be automatically destroyed
   when the stream is destroyed. */
SshStream ssh_tr_create_final(SshTransportCommon tr);

/* Disconnects, and optionally sends a disconnect message to the other side. */
void ssh_tr_up_disconnect(SshTransportCommon tr, Boolean locally_generated,
                          Boolean send_to_other_side,
                          unsigned int reason, const char *fmt, ...);

/* Compare version strings.  The first argument is locally stored 
   constant version string and the second argument is a version
   string received from the remote connection.  Strings do not 
   have to be identical for this function to return TRUE.
   For example ssh_tr_version_string_equal("2.0.1", "2.0.1")
   and ssh_tr_version_string_equal("2.0.1", "2.0.1-beta3") return
   TRUE whereas ssh_tr_version_string_equal("2.0.1", "2.0.10")
   and ssh_tr_version_string_equal("2.0.1-beta3", "2.0.1") 
   return FALSE. */
Boolean ssh_tr_version_string_equal(const char *version,
                                    const char *soft_version);

/* Methods table for transport streams. */
extern const SshStreamMethodsTable ssh_tr_methods;

#endif /* TRCOMMON_H */
