/*

  ssh-signer2.c

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1999 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Hostbased authentication, client-side. This program is supposed to
  be suid, as it should have access to the private part of the host
  key.

*/
/*
  
  ssh-signer2 communicates with the ssh2-client with a very simple protocol.

  First, ssh2 will fork and exec ssh-signer2. Then it wraps
  ssh-signer2's stdin and stdout to a sshpipestream. This stream is
  then wrapped to a sshpacketstream. Using this stream it is very easy
  to implement a packet-based protocol.

  Possible messages from ssh2 to ssh-signer2:

  #define SSH_AUTH_HOSTBASED_PACKET    (SshPacketType)1

    If this is received, ssh-signer2 begins to check for the packet's
    validity. As ssh-signer2 has (should have) access to the client
    host's hostkey, it shouldn't sign everything it
    receives. Particularly the client host's name and user's name in
    the client host are important.

    This messages payload is packet, which is formatted according to
    the ssh-userauth draft, under hostbased-authentication.
    
  Other possible 'message' is EOF from the stream, which notifies
  ssh-signer2 that ssh2 client no longer needs ssh-signer2.

  Possible messages from ssh-signer2 to ssh2:
  
  #define SSH_AUTH_HOSTBASED_SIGNATURE (SshPacketType)2

    This message is sent by ssh-signer2 to ssh2 when it has checked
    the packet and signed it. Payload is the signature.
    
  #define SSH_AUTH_HOSTBASED_ERROR     (SshPacketType)3

    This message is sent by ssh-signer2 to ssh2 when it has
    encountered an error during signing or checking the packet. This
    message has no payload.  
*/


#include "ssh2includes.h"
#include "sshpacketstream.h"
#include "sshunixeloop.h"
#include "sshunixfdstream.h"
#include "sshencode.h"
#include "ssh-signer2.h"
#include "sshmsgs.h"
#include "sshauth.h"
#include "sshconfig.h"
#include "sshuserfiles.h"
#include "ssh2pubkeyencode.h"
#include "sshtcp.h"
#include "sshconfig.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshSigner2"

/* Define this to get hexdumps */
/* #define HEXDUMPS */

/* Define this to get debug messages */
/* #define SIGNER_DEBUG */

/* Define this to make ssh-signer2 sleep for 30 seconds after it's
   start. (Only useful in debugging.)*/
/* #define SLEEP_AFTER_STARTUP */

/* Define this to make ssh-signer2 really quiet. */
#define SIGNER_QUIET

static char *progname;

void signer_can_send(void *context);

typedef struct SshSignerRec
{
  /* Parameters for callbacks*/
  unsigned char *packet_payload;
  size_t packet_payload_len;
  Boolean packet_waiting;
  
  /* Internal stuff */
  SshRandomState random_state;
  SshConfig config;
  SshUser effective_user_data;
  Boolean quiet;
  SshPacketWrapper wrapper;
} *SshSigner;

void signer_init_context(SshSigner signer)
{
  signer->packet_payload = NULL;
  signer->packet_payload_len = -1;
  signer->packet_waiting = FALSE;
  signer->random_state = NULL;
  signer->config = NULL;
  signer->effective_user_data = NULL;
  signer->quiet = FALSE ;
  signer->wrapper = NULL;
}

void signer_free_context(SshSigner signer)
{
  static Boolean destroyed = FALSE;

  if (destroyed)
    return;

  destroyed = TRUE;
  
  SSH_DEBUG(3, ("Destroying SshSigner-struct..."));
  ssh_packet_wrapper_destroy(signer->wrapper);
  ssh_xfree(signer->packet_payload);
  ssh_random_free(signer->random_state);
  ssh_config_free(signer->config);
  ssh_user_free(signer->effective_user_data, FALSE);
  ssh_xfree(signer);
  SSH_DEBUG(3, ("done."));
}

void signer_destroy_timeout(void *context)
{
  SshSigner signer = (SshSigner) context;
  SSH_DEBUG(2, ("Destroy timeout. Client didn't send " \
                "End-Of-File soon enough."));
  signer_free_context(signer);
  exit(1);
}

void signer_received_packet(SshPacketType type,
                            const unsigned char *data, size_t len,
                            void *context)
{
  /* Received. */
  unsigned int msg_byte; /* This is unsigned int because
                            SSH_FORMAT_CHAR expects uint; caused a
                            rather nasty bug during development (I
                            used SshUInt8, which wasn't long
                            enough => ssh_decode_array blew the
                            stack).*/
  char *userauth_str, *hostbased_str, *recv_pubkey_alg, *recv_hostname;
  char *recv_username;
  unsigned char *recv_pubkeyblob;
  size_t recv_pubkeyblob_len;
  /* Dug up by us. */
  char *pubkey_alg, *hostname, *username;
  unsigned char *pubkeyblob;
  size_t pubkeyblob_len;
  size_t hostname_len;
  
  /* Internal stuff*/
  SshSigner signer = (SshSigner) context;
  char hostkeyfile[512];
  char *comment;
  SshPrivateKey privkey;
  size_t sig_len, length_return;
  unsigned char *signature_buffer;
  SshCryptoStatus result;
  SshUser real_user;
  
  SSH_TRACE(2, ("Packet received."));

  switch(type)
    {
    case SSH_AUTH_HOSTBASED_PACKET:
      /* Check packet out, and if it's ok, sign it and send
         signature to ssh2. */

#ifdef HEXDUMPS
      SSH_DEBUG_HEXDUMP(3, ("packet:"), \
                        data, len);
#endif /* HEXDUMPS */
      
      if (ssh_decode_array(data, len,
                           /* session id */
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           /* SSH_MSG_USERAUTH_REQUEST (must be checked)*/
                           SSH_FORMAT_CHAR, &msg_byte,
                           /* user name */
                           SSH_FORMAT_UINT32_STR, NULL, NULL,
                           /* service "ssh-userauth" (must be checked)*/
                           SSH_FORMAT_UINT32_STR, &userauth_str, NULL,
                           /* "hostbased" (must be checked)*/
                           SSH_FORMAT_UINT32_STR, &hostbased_str, NULL,
                           /* public key algorithm for hostkey (must
                              be checked)*/                        
                           SSH_FORMAT_UINT32_STR, &recv_pubkey_alg, NULL,
                           /* public hostkey and certificates (must be
                              checked)*/
                           SSH_FORMAT_UINT32_STR, &recv_pubkeyblob,
                           &recv_pubkeyblob_len,
                           /* client host name (must be checked)*/
                           SSH_FORMAT_UINT32_STR, &recv_hostname, NULL,
                           /* user name on client host (must be checked) */
                           SSH_FORMAT_UINT32_STR, &recv_username, NULL,
                           SSH_FORMAT_END) != len || len == 0)
        {
          /* There was an error. */
          SSH_TRACE(0, ("Invalid packet."));
          goto error;     
        }

      /* Get pubkeyblob, pubkeyblob_len, pubkey_alg, hostname and
         username. */

      /* Dig up hosts publickey. */
      if(signer->config->public_host_key_file[0] != '/')
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s/%s", SSH_SERVER_DIR,
                   signer->config->public_host_key_file);
        }
      else
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s",
                   signer->config->public_host_key_file);  
        }

      SSH_TRACE(2, ("place to look for public key: %s", hostkeyfile));
      
      /* This pubkey*-stuff is for the client _host's_ public
         hostkey. */
      /* Getting pubkeyblob, pubkeyblob_len */
      SSH_DEBUG(4, ("Reading pubkey-blob from %s...", hostkeyfile));
      if (ssh2_key_blob_read(signer->effective_user_data, hostkeyfile, NULL,
                             &pubkeyblob,
                             &pubkeyblob_len, NULL) 
          != SSH_KEY_MAGIC_PUBLIC)
        {         
          SSH_TRACE(1, ("Reading public key failed."));
          goto error;
        }
      
      SSH_DEBUG(4, ("done."));
      
      if ((pubkey_alg =
           ssh_pubkeyblob_type(pubkeyblob, pubkeyblob_len))
          == NULL)
        {
          SSH_TRACE(1, ("Couldn't figure out public key algorithm."));
          goto error;
        }

      /* Getting hostname. */
      hostname = ssh_xmalloc(MAXHOSTNAMELEN + 1);
      ssh_tcp_get_host_name(hostname, MAXHOSTNAMELEN + 1);
      hostname_len = strlen(hostname);
      /* Sanity check */
      SSH_ASSERT(hostname_len + 2 < MAXHOSTNAMELEN);
      /* We want FQDN. */
      hostname[hostname_len] = '.';
      hostname[hostname_len + 1] = '\0';
      
      /* Getting username. */
      real_user = ssh_user_initialize(NULL, FALSE);
      username = ssh_xstrdup(ssh_user_name(real_user));
      ssh_user_free(real_user, FALSE);
      
      /* Check all parameters. */
      if (msg_byte != SSH_MSG_USERAUTH_REQUEST)
        {         
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("msg_byte != SSH_MSG_USERAUTH_REQUEST " \
                        "(msg_byte = %d)", msg_byte));
          goto error;
        }
      if (strcmp(userauth_str, SSH_USERAUTH_SERVICE) != 0)
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("userauth_str != \"ssh-userauth\" (it was '%s')", \
                        userauth_str));
          goto error;
        }
      if (strcmp(hostbased_str, SSH_AUTH_HOSTBASED) != 0)
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("hostbased_str != \"hostbased\" (it was '%s')", \
                        hostbased_str));
          goto error;
        }
      /* XXX has to be change when adding support for multiple hostkeys */
      if (strcmp(recv_pubkey_alg, pubkey_alg) != 0)
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("Client gave us invalid pubkey-algorithms for our " \
                        "hostkey."));
          goto error;
        }
      
      if (recv_pubkeyblob_len == pubkeyblob_len)
        {
          if (memcmp(recv_pubkeyblob, pubkeyblob, pubkeyblob_len) != 0)
            {
              SSH_TRACE(1, ("Invalid packet."));
              SSH_DEBUG(1, ("client gave us wrong (or corrupted) " \
                            "public key."));
#ifdef HEXDUMPS
              SSH_DEBUG_HEXDUMP(3, ("client gave us:"), \
                                recv_pubkeyblob, pubkeyblob_len);
              SSH_DEBUG_HEXDUMP(3, ("our pubkey:"), \
                                recv_pubkeyblob, pubkeyblob_len);
#endif /* HEXDUMPS */
              goto error;
            }
        }
      else
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("Client gave us wrong (or corrupted) public key. " \
                        "Lengths differ (received: %d ; ours: %d)", \
                        recv_pubkeyblob_len, pubkeyblob_len));
          goto error;
        }

      if (strcmp(recv_hostname, hostname) != 0)
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("Wethinks the client gave us the wrong hostname. " \
                        "(client's opinion: '%s' ours: '%s'", \
                        recv_hostname, hostname));
          goto error;
        }
      if (strcmp(recv_username, username) != 0)
        {
          SSH_TRACE(1, ("Invalid packet."));
          SSH_DEBUG(1, ("Client definitely gave us the wrong user name. " \
                        "(it says: '%s' we know: '%s')", recv_username, \
                        username));
          goto error;
        }
      
      /* Sign the packet and send it to client. */
      
      /* If we've gotten this far, the packet is ok, and it can be
         signed. */

      SSH_TRACE(0, ("Received packet ok."));
      if(signer->config->public_host_key_file[0] != '/')
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s/%s", SSH_SERVER_DIR,
                   signer->config->host_key_file);
        }
      else
        {
          snprintf(hostkeyfile, sizeof(hostkeyfile), "%s",
                   signer->config->host_key_file);  
        }

      SSH_TRACE(2, ("place to look for private key: %s", hostkeyfile));

      if ((privkey = ssh_privkey_read(signer->effective_user_data, hostkeyfile, "", 
                                      &comment, NULL)) == NULL)
        ssh_fatal("ssh_privkey_read from %s failed.", hostkeyfile);

      /* Check how big a chunk our private key can sign (this is
         purely a sanity check, as both of our signature schemas do
         their own hashing) */
      sig_len = ssh_private_key_max_signature_input_len(privkey);

      SSH_TRACE(2, ("max input length for signing: %d", sig_len));
      
      if (sig_len == 0)
        {
          SSH_TRACE(0, ("private key not capable of signing! " \
                        "(definitely an error)"));
          goto error;
        }
      else if (sig_len != -1 && sig_len < len)
        {
          SSH_TRACE(0, ("private key can't sign our data. (too much " \
                        "data (data_len %d, max input len for signing " \
                        "%d))", len, sig_len));
          goto error;
        }

      /* Now check how much we much buffer we must allocate for the
         signature. */
      sig_len = ssh_private_key_max_signature_output_len(privkey);

      SSH_TRACE(2, ("max output length for signature: %d", sig_len));
      
      signature_buffer = ssh_xcalloc(sig_len, sizeof(unsigned char));

      /* Do the actual signing. */

#ifdef HEXDUMPS
      SSH_DEBUG_HEXDUMP(5, ("Signing following data"),
                        data + 4, len - 4);
#endif /* HEXDUMPS */
      
      if ((result = ssh_private_key_sign(privkey,
                                         data,
                                         len,
                                         signature_buffer,
                                         sig_len,
                                         &length_return,
                                         signer->random_state))
          != SSH_CRYPTO_OK)
        {
          SSH_TRACE(0, ("ssh_private_key_sign() returned %d.", result));
          goto error;
        }

#ifdef HEXDUMPS      
      SSH_DEBUG_HEXDUMP(5, ("Signature"), signature_buffer, length_return);
#endif /* HEXDUMPS */
      /* Send it to client. */
      signer->packet_payload = signature_buffer;
      signer->packet_payload_len = length_return;
      signer->packet_waiting = TRUE;

      if (ssh_packet_wrapper_can_send(signer->wrapper))
        signer_can_send(signer);
      
      /* XXX free dynamically allocated data. */
      ssh_xfree(username);

      break;
    case SSH_AUTH_HOSTBASED_SIGNATURE:
      /* We shouldn't get this type of packet. This is an error.*/
      SSH_TRACE(0, ("client sent us SSH_AUTH_HOSTBASED_SIGNATURE. This " \
                    "is an error."));
      goto error;
      break;
    case SSH_AUTH_HOSTBASED_ERROR:
      /* We shouldn't be getting this either. This is an error. */
      SSH_TRACE(0, ("client sent us SSH_AUTH_HOSTBASED_SIGNATURE_ERROR. " \
                    "This is an error. (This message can be sent by " \
                    "ssh-signer2 only)"));
      goto error;
      break;
    }
  return;

  /* We come here after errors. */
 error:
  /* Send error message to ssh2, and wait for ssh2 to send
     EOF. */
  ssh_packet_wrapper_send_encode(signer->wrapper, SSH_AUTH_HOSTBASED_ERROR,
                                 SSH_FORMAT_END);

  /* Init a 5 second timeout. If ssh2 hasn't disconnected at
     that time, close stream.*/
  ssh_register_timeout(5L, 0L, signer_destroy_timeout, signer);
  
  return;
}

void signer_received_eof(void *context)
{
  SshSigner signer = (SshSigner)context;
  
  /* Cancel self-destruct. */
  ssh_cancel_timeouts(signer_destroy_timeout, SSH_ALL_CONTEXTS);

  SSH_TRACE(0, ("EOF received from packetstream. Exiting."));

  signer_free_context(signer);
  
  exit(0);
}

void signer_can_send(void *context)
{
  SshSigner signer = (SshSigner) context;

  static Boolean packet_already_sent = FALSE;
  
  SSH_ASSERT(signer != NULL);

  if (packet_already_sent)
    return;
  else
    packet_already_sent = TRUE;
  

  if (signer->packet_waiting)
    {
      /* send packet */
      SSH_TRACE(0, ("Sending signature to ssh2-client."));

      ssh_packet_wrapper_send_encode(signer->wrapper,
                                     SSH_AUTH_HOSTBASED_SIGNATURE,
                                     SSH_FORMAT_UINT32_STR,
                                     signer->packet_payload,
                                     signer->packet_payload_len,
                                     SSH_FORMAT_END);
      
      signer->packet_waiting = FALSE;
    }
}

void signer_ssh_fatal(const char *message, void *context)
{
  fprintf(stderr, "%s:FATAL:%s\n", progname, message);
  fflush(stderr);
}

void signer_ssh_warning(const char *message, void *context)
{
  SshSigner signer = (SshSigner) context;

  if (!signer->quiet)
    fprintf(stderr, "%s:%s\n", progname, message);
  fflush(stderr);
}

void signer_ssh_debug(const char *message, void *context)
{
  SshSigner signer = (SshSigner) context;

  if (!signer->quiet)
    fprintf(stderr, "%s:%s\n", progname, message);
  fflush(stderr);
}

int main(int argc, char **argv)
{
  SshStream stdio_stream;
  SshSigner signer;
  char config_filename[512];
  char *temp_name;
  
#ifdef SLEEP_AFTER_STARTUP 
  sleep(30);
#endif /* SLEEP_AFTER_STARTUP */

  /* Get program name (without path). */
  if ((temp_name = strrchr(argv[0], '/')) != NULL)
    progname = ssh_xstrdup(temp_name + 1);
  else
    progname = ssh_xstrdup(argv[0]);

  /* XXX there should be a way to give command-line parameters to this
     program, but, they should only be used if the uid is the same as
     euid. */
  ssh_event_loop_initialize();
  
  signer = ssh_xcalloc(1, sizeof(*signer));

#ifdef SIGNER_QUIET
  signer->quiet = TRUE;
#else /* SIGNER_QUIET */
  signer->quiet = FALSE;
#endif /* SIGNER_QUIET */
  ssh_debug_register_callbacks(signer_ssh_fatal, signer_ssh_warning,
                               signer_ssh_debug, (void *)signer);
#ifdef SIGNER_DEBUG
  ssh_debug_set_global_level(5);
#endif /* SIGNER_DEBUG */
  
  /* Act as server. */
  signer->config = ssh_server_create_config();

  SSH_TRACE(2, ("public key file: %s", signer->config->public_host_key_file));
  SSH_TRACE(2, ("private key file: %s", signer->config->host_key_file));
  SSH_TRACE(2, ("randomseed file: %s", signer->config->random_seed_file));
  
  /* Initialize user context with euid. This is used to dig up the
     hostkey and such. */
  signer->effective_user_data = ssh_user_initialize_with_uid(geteuid(), FALSE);

  signer->random_state = ssh_randseed_open(signer->effective_user_data,
                                           signer->config);
  
  /* XXX what about alternative config files? This should be possible
     to configure somehow. An option for configure is probably a good
     idea. */
  snprintf(config_filename, sizeof(config_filename), "%s/%s",
           SSH_SERVER_DIR, SSH_SERVER_CONFIG_FILE);

  if (!ssh_config_read_file(signer->effective_user_data, signer->config,
                            NULL, config_filename, NULL))
    ssh_warning("%s: Failed to read config file %s", argv[0],
                config_filename);

  stdio_stream = ssh_stream_fd_wrap2(fileno(stdin), fileno(stdout),
                                     TRUE);

  signer->wrapper = ssh_packet_wrap(stdio_stream,
                            signer_received_packet,
                            signer_received_eof,
                            signer_can_send,
                            signer);
  
  ssh_event_loop_run();

  return 0;
}
