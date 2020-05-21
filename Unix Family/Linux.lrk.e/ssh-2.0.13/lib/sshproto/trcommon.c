/*

trcommon.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

/*
 * $Id: trcommon.c,v 1.58 1999/05/04 19:21:12 kivinen Exp $
 * $Log: trcommon.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbufaux.h"
#include "sshgetput.h"
#include "namelist.h"
#include "sshcipherlist.h"
#include "sshtimeouts.h"
#include "sshtcp.h"
#include "sshtrans.h"
#include "sshmsgs.h"
#include "sshencode.h"
#include "trcommon.h"
#include "trkex.h"
#include "ssh2pubkeyencode.h"

#define SSH_DEBUG_MODULE "Ssh2Transport"

void ssh_tr_process_output(SshTransportCommon tr);
void ssh_tr_process_input(SshTransportCommon tr);

/* Define this to dump packet contents. */
#undef DUMP_PACKETS

/* Performs cleanups after a key exchange.  This can also be used to
   prepare for a new key exchange. */

void ssh_tr_kex_cleanup(SshTransportCommon tr)
{
  SSH_DEBUG(5, ("ssh_tr_kex_cleanup"));

  if (tr->client_kexinit_packet)
    {
      ssh_buffer_free(tr->client_kexinit_packet);
      tr->client_kexinit_packet = NULL;
    }
  if (tr->server_kexinit_packet)
    {
      ssh_buffer_free(tr->server_kexinit_packet);
      tr->server_kexinit_packet = NULL;
    }
  if (tr->client_kex1_packet)
    {
      ssh_buffer_free(tr->client_kex1_packet);
      tr->client_kex1_packet = NULL;
    }
  if (tr->server_kex1_packet)
    {
      ssh_buffer_free(tr->server_kex1_packet);
      tr->server_kex1_packet = NULL;
    }
  if (tr->server)
    {
      /* XXX */
    }
  else
    {
      if (tr->public_host_key_blob)
        {
          ssh_buffer_free(tr->public_host_key_blob);
          tr->public_host_key_blob = NULL;
        }
      if (tr->public_host_key)
        {
          ssh_public_key_free(tr->public_host_key);
          tr->public_host_key = NULL;
        }
      if (tr->public_server_key)
        {
          ssh_public_key_free(tr->public_server_key);
          tr->public_server_key = NULL;
        }
    }
}

/* Destroys our context immediately.  This means that we will release all
   resources now. */

void ssh_tr_destroy_now(SshTransportCommon tr)
{
  SSH_DEBUG(5, ("ssh_tr_destroy_now"));
  if (tr == NULL)
    return;
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, (void *)tr);
  ssh_tr_kex_cleanup(tr);
  if (tr->connection)
    ssh_stream_destroy(tr->connection);
  tr->connection = NULL;
  if (tr->params)
    ssh_transport_destroy_params(tr->params);
  ssh_buffer_uninit(&tr->outgoing);
  if (tr->incoming_packet)
    ssh_buffer_free(tr->incoming_packet);
  assert(tr->up_stream == NULL);  /* Should be... */
  tr->up_callback = NULL;
  ssh_buffer_uninit(&tr->up_outgoing);
  ssh_buffer_uninit(&tr->up_incoming);
  ssh_xfree(tr->own_version);
  ssh_xfree(tr->guessed_kex);
  ssh_xfree(tr->guessed_host_key);
  ssh_xfree(tr->kex_name);
  ssh_xfree(tr->host_key_name);
  ssh_xfree(tr->host_key_names);
  ssh_xfree(tr->c_to_s.cipher_name);
  ssh_xfree(tr->c_to_s.mac_name);
  ssh_xfree(tr->c_to_s.compression_name);
  ssh_xfree(tr->s_to_c.cipher_name);
  ssh_xfree(tr->s_to_c.mac_name);
  ssh_xfree(tr->s_to_c.compression_name);
  if (tr->hash)
    ssh_hash_free(tr->hash);
  if (tr->outgoing_cipher)
    ssh_cipher_free(tr->outgoing_cipher);
  if (tr->incoming_cipher)
    ssh_cipher_free(tr->incoming_cipher);
  if (tr->outgoing_mac)
    ssh_mac_free(tr->outgoing_mac);
  if (tr->incoming_mac)
    ssh_mac_free(tr->incoming_mac);
  if (tr->compression_outgoing)
    ssh_compress_free(tr->compression_outgoing);
  if (tr->compression_incoming)
    ssh_compress_free(tr->compression_incoming);
  if (tr->compression_buffer)
    ssh_buffer_free(tr->compression_buffer);
  ssh_xfree(tr->service_name);
  if (tr->public_server_key)
    ssh_public_key_free(tr->public_host_key);
  if (tr->public_server_key)
    ssh_public_key_free(tr->public_server_key);
  if (tr->public_host_key_blob)
    ssh_buffer_free(tr->public_host_key_blob);
  if (tr->public_server_key_blob)
    ssh_buffer_free(tr->public_server_key_blob);
  if (tr->private_host_key)
    ssh_private_key_free(tr->private_host_key);
  if (tr->private_server_key)
    ssh_private_key_free(tr->private_server_key);

  memset(tr->session_identifier, 0, tr->session_identifier_len);
  memset(tr->exchange_hash, 0, tr->exchange_hash_len);

  /* clear and free dh key exchange stuff */

  ssh_mp_clear(tr->dh_p);
  ssh_mp_clear(tr->dh_g);
  ssh_mp_clear(tr->dh_e);
  ssh_mp_clear(tr->dh_f);
  ssh_mp_clear(tr->dh_k);
  ssh_mp_clear(tr->dh_secret);

  /* Fill with garbage for debugging. */
  memset(tr, 'F', sizeof(*tr));
  ssh_xfree(tr);
}

/* Called from the bottom of the event loop, we try to process input from
   the connection.  This will restart automatic reading. */

void ssh_tr_process_input_proc(void *context)
{
  SshTransportCommon tr = context;

  ssh_tr_process_input(tr);
}

/* Ensure that we will proceed reading, even if reading was previously
   blocked. */

void ssh_tr_wake_up_input(SshTransportCommon tr)
{
  SSH_DEBUG(5, ("ssh_tr_wake_up_input"));

  /* If reads not blocked, just return. */
  if (!tr->read_has_blocked)
    return;

  tr->read_has_blocked = FALSE;
  ssh_register_timeout(0L, 0L, ssh_tr_process_input_proc, (void *)tr);
}

/* Call the application callback.  This is called from the event loop only. */

void ssh_tr_up_signal_input_proc(void *context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(7, ("ssh_tr_up_signal_input_proc"));

  if (tr->up_callback)
    (*tr->up_callback)(SSH_STREAM_INPUT_AVAILABLE, tr->up_context);
}

/* Call the application callback.  This is called from the event loop only. */

void ssh_tr_up_signal_output_proc(void *context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(7, ("ssh_tr_up_signal_output_proc"));

  if (tr->up_callback)
    (*tr->up_callback)(SSH_STREAM_CAN_OUTPUT, tr->up_context);
}

/* Signal that the application can read. */

void ssh_tr_up_signal_input(SshTransportCommon tr)
{
  SSH_DEBUG(7, ("ssh_tr_up_signal_input"));
  if (tr->up_callback)
    ssh_register_timeout(0L, 0L, ssh_tr_up_signal_input_proc, (void *)tr);
}

/* Signal that the application can write. */

void ssh_tr_up_signal_output(SshTransportCommon tr)
{
  SSH_DEBUG(7, ("ssh_tr_up_signal_output"));
  if (tr->up_callback)
    ssh_register_timeout(0L, 0L, ssh_tr_up_signal_output_proc, (void *)tr);
}

/* Sends a packet upstream.  Buffers the given data, and signals a wakeup
   for the stream if appropriate. */

void ssh_tr_up_send(SshTransportCommon tr, SshCrossPacketType type,
                    const unsigned char *payload, size_t len)
{
  SSH_DEBUG(7, ("ssh_tr_up_send %d", type));
  /* Wake up reads from up if they have blocked. */
  if (tr->up_read_blocked)
    ssh_tr_up_signal_input(tr);

  /* Add data to the upwards outgoing buffer. */
  buffer_put_int(&tr->up_outgoing, (len + 1));
  buffer_put_char(&tr->up_outgoing, (int)type);
  ssh_buffer_append(&tr->up_outgoing, payload, len);
}

/* Send as much data as possible from the outgoing buffer.  Return TRUE
   if all data was sent and processing can continue, and FALSE if an
   error occurred or we can do no more. */

Boolean ssh_tr_output_outgoing(SshTransportCommon tr)
{
  int len;
  SSH_DEBUG(7, ("ssh_tr_output_outgoing"));

  while (ssh_buffer_len(&tr->outgoing) > 0)
    {
      len = ssh_buffer_len(&tr->outgoing);
      len = ssh_stream_write(tr->connection, 
                             ssh_buffer_ptr(&tr->outgoing), 
                             len);
      if (len < 0)
        {
          SSH_DEBUG(6, ("ssh_tr_output_outgoing: cannot write more now"));
          return FALSE;    /* We cannot write more at this time. */
        }
      if (len == 0)
        {
          /* We cannot write any more; presumably the connection has been
             lost. */
          ssh_tr_up_disconnect(tr, TRUE, FALSE,
                               SSH_DISCONNECT_CONNECTION_LOST,
                               "Connection lost on output.");
          ssh_buffer_clear(&tr->outgoing);
          return FALSE;
        }
      ssh_buffer_consume(&tr->outgoing, len);
    }

  /* Send an eof to the connection if requested. */
  if (tr->outgoing_eof)
    ssh_stream_output_eof(tr->connection);

  /* Check if we should destroy the context next */
  if (tr->up_stream == NULL)
    {
      ssh_tr_destroy_now(tr);
      return FALSE;
    }

  /* Wake up writes from up if enough space in buffer. */
  if (tr->up_write_blocked &&
      ssh_buffer_len(&tr->up_outgoing) <
      XMALLOC_MAX_SIZE - SSH_MAX_TOTAL_PACKET_LENGTH - SSH_CONTROL_RESERVE &&
      ssh_buffer_len(&tr->outgoing) < SSH_BUFFERING_LIMIT)
    {
      SSH_DEBUG(6, ("ssh_tr_output_outgoing: waking up application output"));
      tr->up_write_blocked = FALSE;
      ssh_tr_up_signal_output(tr);
    }

  SSH_DEBUG(6, ("ssh_tr_output_outgoing: no more data to write"));
  return TRUE;
}

/* Wraps the packet structure around the payload in the buffer,
   and sends it out. */

void ssh_tr_send_packet(SshTransportCommon tr,
                        const unsigned char *payload,
                        size_t payload_length)
{
  size_t block_size, length, padding_length, mac_length;
  int i;
  unsigned char *start;
  unsigned char seq_buf[4];

  SSH_DEBUG(6, ("ssh_tr_send_packet %d", payload[0]));

  if (tr->outgoing_eof)
    {
      /* Trying to send after we have sent EOF??? */
      ssh_debug("ssh_tr_send_packet: trying to send after EOF.");
      return;
    }
  
  /* Compress the payload if appropriate. */
  tr->uncompressed_outgoing_bytes += payload_length;
  if (!ssh_compress_is_none(tr->compression_outgoing))
    {
      ssh_buffer_clear(tr->compression_buffer);
      ssh_compress_buffer(tr->compression_outgoing, payload, payload_length,
                          tr->compression_buffer);
      payload = ssh_buffer_ptr(tr->compression_buffer);
      payload_length = ssh_buffer_len(tr->compression_buffer);
    }
  tr->compressed_outgoing_bytes += payload_length;
  
  /* Compute restrictions for encryption block size. */
  block_size = ssh_cipher_get_block_length(tr->outgoing_cipher);
  if (block_size < 8)
    block_size = 8;

  mac_length = ssh_mac_length(tr->outgoing_mac);
  
  /* Compute padding length and the total length */

  length = 1 + 4 + payload_length;
  padding_length = block_size - (length % block_size);
  if (padding_length < 4) 
    padding_length += block_size;
  
  length += padding_length;  /* now everything but the mac */

  SSH_DEBUG(6, ("ssh_tr_send_packet: length %d pad %d payload %d mac %d",
            length, padding_length, payload_length, mac_length));

  /* Store the plaintext packet in the buffer. */

  ssh_buffer_append_space(&tr->outgoing, &start, length + mac_length);
  SSH_PUT_32BIT(start, length - 4);  /* not including the length itself */
  start[4] = padding_length;
  memcpy(4 + 1 + start, payload, payload_length);

  for (i = 0; i < padding_length; i++)
    start[4 + 1 + payload_length + i] = ssh_random_get_byte(tr->random_state);
  

#ifdef DUMP_PACKETS
  ssh_debug("Dumping outgoing...");
  buffer_dump(&tr->outgoing);
#endif /* DUMP_PACKETS */

  /* Compute and store MAC. */

  switch (tr->ssh_old_mac_bug_compat)
    {
    case FALSE: /* Everything is a-ok */
      ssh_mac_start(tr->outgoing_mac);
      SSH_PUT_32BIT(seq_buf, tr->outgoing_sequence_number);
      ssh_mac_update(tr->outgoing_mac, seq_buf, 4);
      ssh_mac_update(tr->outgoing_mac, start, length);
      ssh_mac_final(tr->outgoing_mac, start + length);
      break;
    case TRUE: /* other side counts the MAC in the old (==wrong) way. */
      ssh_mac_start(tr->outgoing_mac);
      ssh_mac_update(tr->outgoing_mac, start, length);
      SSH_PUT_32BIT(seq_buf, tr->outgoing_sequence_number);
      ssh_mac_update(tr->outgoing_mac, seq_buf, 4);
      ssh_mac_final(tr->outgoing_mac, start + length);
      break;
    default:
      ssh_fatal("ssh_tr_send_packet: Whoah! How can a Boolean value be"
                " something else than TRUE or FALSE?");
    }
  
  /* Encrypt the packet (but not the MAC). */
  ssh_cipher_transform(tr->outgoing_cipher, start, start, length);

  /* Increment the packet sequence number. */
  tr->outgoing_sequence_number++;

#ifdef DUMP_PACKETS
  ssh_debug("-- encrypted --");
  buffer_dump(&tr->outgoing);
#endif /* DUMP_PACKETS */
  
  /* Start writing if not already active. */
  ssh_tr_output_outgoing(tr);
}

/* Terminates the protocol, and sends a disconnect message up. */

void ssh_tr_up_disconnect(SshTransportCommon tr,
                          Boolean locally_generated,
                          Boolean send_to_other_side,
                          unsigned int reason,
                          const char *fmt, ...)
{
  SshBuffer buffer;
  char message[512];
  va_list va;

  SSH_DEBUG(5, ("ssh_tr_up_disconnect %d %.100s", reason, fmt));

  if (tr->up_outgoing_eof)
    {
      /* We are already disconnected - just return. */
      ssh_debug("ssh_tr_up_disconnect: already disconnected.");
      return;
    }

  /* Format the message. */
  va_start(va, fmt);
  vsnprintf(message, sizeof(message), fmt, va);
  va_end(va);
  
  SSH_DEBUG(5, ("ssh_tr_up_disconnect %d '%.200s'", (int)reason, message));

  /* If appropriate, send the disconnect to the other side. */
  if (send_to_other_side)
    {
      ssh_buffer_init(&buffer);
      buffer_put_char(&buffer, SSH_MSG_DISCONNECT);
      buffer_put_int(&buffer, reason);
      buffer_put_uint32_string(&buffer, message, strlen(message));
      buffer_put_uint32_string(&buffer, "en", 2);
      ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      ssh_buffer_uninit(&buffer);
    }
  
  /* Format the upstream packet payload. */
  ssh_buffer_init(&buffer);
  buffer_put_boolean(&buffer, locally_generated);
  buffer_put_int(&buffer, reason);
  buffer_put_uint32_string(&buffer, message, strlen(message));
  buffer_put_uint32_string(&buffer, "en", 2);

  /* Send and free the packet. */
  ssh_tr_up_send(tr, SSH_CROSS_DISCONNECT,
                 ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);

  /* Prepare for shutdown. */
  tr->up_outgoing_eof = TRUE;
  tr->received_state = RECEIVED_DEAD;
  tr->sent_state = SENT_DEAD;
  tr->outgoing_eof = TRUE;
  ssh_tr_output_outgoing(tr);
}

/* Read in version number.  This returns TRUE if more input may be
   available and reading should continue. */

Boolean ssh_tr_input_version(SshTransportCommon tr)
{
  int len;
  char *verstring_p, *temp_verstring;
#if 1
  static int string_index = 0;
  /* XXX This should be done a bit smarter, as we MAY display the
     information sent by the server.*/
  static char temp_string[100];
  
  SSH_DEBUG(5, ("ssh_tr_input_version"));

  /* According to the draft: The server MAY send other lines of
     data before sending the version string.  Each line SHOULD be
     terminated by a carriage return and newline.  Such lines MUST NOT
     begin with "SSH-""... */

  /* check if we havent received 'SSH-' and we are client */
  if (tr->remote_version_index == 0 && !tr->server)
    {
      for (;;)
        {
          /* Read a single character.  We cannot read more as we are
             waiting 'SSH-' */
          len = ssh_stream_read(tr->connection,
                                (unsigned char *)temp_string +
                                string_index, 1);
          if (len == 0)
            {
              ssh_tr_up_disconnect(tr, TRUE, FALSE,
                                   SSH_DISCONNECT_CONNECTION_LOST,
                                   "Connection closed by remote host.");
              return FALSE;
            }
          if (len < 0)
            return FALSE; /* No more data available yet. */

          /* Check if we have a match */
          if (!memcmp(&temp_string[string_index - 3], "SSH-", 4))
            {
              memmove(tr->remote_version, "SSH-", 4);
              tr->remote_version_index = 4;
              break;
            }
          
          /* Don't read it too much. Wrap around. (It would be
             against the draft to disconnect. Theoretically, the
             server should be allowed to send the collected works
             of Shakespeare if it wanted to.) */
          if (string_index >= sizeof(temp_string) - 1)
            {
              /* Move the last 4 read chars to the beginning, so we
                 don't lose any part of the (possible) version string */
              memmove(temp_string, &temp_string[string_index - 4], 4);
              string_index = 4;
              continue;
            }

          /* Count these characters. */
          string_index++;
        }
    }
#endif /* 0 or 1 */  
  /* Keep reading until the version identifier has been received. */
  for (;;)
    {
      /* Is it too long? */
      if (tr->remote_version_index == sizeof(tr->remote_version) - 1)
        {
          ssh_tr_up_disconnect(tr, TRUE, FALSE,
                               SSH_DISCONNECT_PROTOCOL_ERROR,
                               "Remote protocol version too long.");
          return FALSE;
        }
      
      /* Read a single character.  We cannot read more as we are waiting
         for a newline. */
      len = ssh_stream_read(tr->connection, (unsigned char *) 
                            tr->remote_version + tr->remote_version_index, 1);
      if (len == 0)
        {
          ssh_tr_up_disconnect(tr, TRUE, FALSE,
                               SSH_DISCONNECT_CONNECTION_LOST,
                               "Connection closed by remote host.");
          return FALSE;
        }
      if (len < 0)
        return FALSE; /* No more data available yet. */
      
      /* Check if we are at end of version id. Note that we don't include the
         newline in the version number string. */
      if (tr->remote_version[tr->remote_version_index] == '\n')
        break;

      if (tr->remote_version[tr->remote_version_index] == '\r')
        continue;  /* Ignore carriage return. */
      
      /* Count these characters. */
      tr->remote_version_index++;
    }

  /* Null-terminate the version number. */
  tr->remote_version[tr->remote_version_index] = '\0';

  SSH_DEBUG(0, ("Remote version: %s", tr->remote_version));
  
  /* Call the version callback, so that it can check for ssh1 compatibility. */
  if (tr->version_callback)
    (*tr->version_callback)(tr->remote_version, tr->version_context);
  
  /* This version of ssh will only talk to a SSH 2.0 host. */
  if (strncmp(tr->remote_version, "SSH-2.", 6) != 0 &&
      strncmp(tr->remote_version, "SSH-1.99", 8) != 0)
    {
      ssh_tr_up_disconnect(tr, TRUE, FALSE,
                           SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                           "Illegal protocol version.");
      
      return FALSE;
    }

  /* Compatibility with older ssh-2.0.x versions */
  
  if ((verstring_p = strchr(tr->remote_version, '-')) != NULL)
    {
      verstring_p++;
      if ((verstring_p = strchr(verstring_p, '-')) != NULL)
        {
          verstring_p++;
          temp_verstring = ssh_xstrdup(verstring_p);
          if ((verstring_p = strchr(temp_verstring, ' ')) != NULL)
            {
              verstring_p = '\0';
            }
          if (ssh_tr_version_string_equal("2.0.6", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.7", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.8", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.9", temp_verstring))
            {
              SSH_DEBUG(5, ("Remote version has MAC calculation order bug."));
              tr->ssh_old_mac_bug_compat = TRUE;
            }
          if (ssh_tr_version_string_equal("2.0.6", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.7", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.8", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.9", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.10", temp_verstring))
            {
              SSH_DEBUG(5, ("Remote version has key size reduction bug."));
              tr->ssh_old_keygen_bug_compat = TRUE;
            }
          if (ssh_tr_version_string_equal("2.0.6", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.7", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.8", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.9", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.10", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.12", temp_verstring) ||
              ssh_tr_version_string_equal("2.0.13.beta5",temp_verstring) ||
              ssh_tr_version_string_equal("2.0.13.beta6",temp_verstring) ||
              ssh_tr_version_string_equal("2.0.13.beta13",temp_verstring))
            {
              SSH_DEBUG(5, ("Remote version has publickey draft " \
                            "incompatibility bug."));
              tr->ssh_old_publickey_bug_compat = TRUE;
            }

          ssh_xfree(temp_verstring);
        }
    }
  
  
  /* We have now received the entire remote version number. */
  tr->received_state = RECEIVED_VERSION;

  /* Try output, as this may enable us to do something new. */
  ssh_tr_process_output(tr);

  return TRUE;
}  

/* Constructs a KEX1 packet, if appropriate for the current kex method and
   algorithms.  Returns the packet payload if one is to be sent, or NULL
   if no such packet should be sent for the current method.  Saves the
   packet as our KEX1 packet.  It is legal to call this multiple times. */

SshBuffer *ssh_tr_make_kex1(SshTransportCommon tr)
{
  SshBuffer *packet;

  SSH_DEBUG(5, ("ssh_tr_make_kex1"));
  
  /* Create the KEX1 packet and save it.  Note that the returned packet may
     also be NULL. */
  if (tr->server)
    {
      packet = (*tr->kex->server_make_kex1)(tr);
      if (tr->server_kex1_packet)
        ssh_buffer_free(tr->server_kex1_packet);
      tr->server_kex1_packet = packet;
    }
  else
    {
      packet = (*tr->kex->client_make_kex1)(tr);
      if (tr->client_kex1_packet)
        ssh_buffer_free(tr->client_kex1_packet);
      tr->client_kex1_packet = packet;
    }

  return packet;
}

/* Constructs a KEX2 packet, if appropriate for the current kex method and
   algorithms.  Returns the packet payload, or NULL if no KEX2 packet is to
   be sent for the current kex method.  The sent state must be updated by the
   caller.  The buffer must eventually be freed by the caller. */

SshBuffer *ssh_tr_make_kex2(SshTransportCommon tr)
{
  SshBuffer *packet;

  SSH_DEBUG(5, ("ssh_tr_make_kex2"));

  /* Create the KEX1 packet and save it.  Note that the returned packet may
     also be NULL. */
  if (tr->server)
    packet = (*tr->kex->server_make_kex2)(tr);
  else
    packet = (*tr->kex->client_make_kex2)(tr);

  return packet;
}

/* Get a string from both the client and the server key exchange packets,
   and choose an algorithm from those.  Returns the chosen algorithm
   (allocated with ssh_xmalloc; the caller must free it with ssh_xfree) or NULL if
   no common algorithm can be found. */

char *ssh_tr_negotiate_one_alg(SshTransportCommon tr,
                               const char *description,
                               SshBuffer *client_kexinit,
                               SshBuffer *server_kexinit)
{
  char *client_list, *server_list, *common_list, *result;

  if (ssh_decode_buffer(client_kexinit,
                        SSH_FORMAT_UINT32_STR, &client_list, NULL,
                        SSH_FORMAT_END) == 0)
    return NULL;
  if (ssh_decode_buffer(server_kexinit,
                        SSH_FORMAT_UINT32_STR, &server_list, NULL,
                        SSH_FORMAT_END) == 0)
    {
      ssh_xfree(client_list);
      return NULL;
    }
  common_list = ssh_name_list_intersection(client_list, server_list);

  if (common_list == NULL)
    return NULL;

  result = strtok(common_list, ",");
  if (result)
    result = ssh_xstrdup(result);
  else
    ssh_debug("ssh_tr_negotiate_one_alg: failed for %s: %.100s vs %.100s",
          description, client_list, server_list);
  ssh_xfree(client_list);
  ssh_xfree(server_list);
  ssh_xfree(common_list);
  return result;
}

/* Assings a new value to the char pointer, freeing the old value if it is
   non-NULL.  The argument string must have been allocated by ssh_xmalloc;
   this does not copy it. */

void ssh_tr_set_string(char **cpp, char *new_value)
{
  if (*cpp != NULL)
    ssh_xfree(*cpp);
  *cpp = new_value;
}

/* Compute the algorithms that result from the negotiation.  This returns
   TRUE if a common set of algorithms was chosen, and FALSE if no compatible
   set of algorithms can be chosen.  If TRUE is returned, this sets
   guess_was_wrong to indicate whether the initial guessed algorithm was
   correct. */

Boolean ssh_tr_negotiate(SshTransportCommon tr,
                         Boolean *guess_was_wrong)
{
  char *client_kex, *server_kex, *common_kex, *kex;
  char *client_server_host_key, *server_server_host_key, *common_host_key;
  char *chosen_kex = NULL, *chosen_host_key = NULL;
  char *chosen_c_to_s_cipher = NULL, *chosen_s_to_c_cipher = NULL;
  char *chosen_c_to_s_mac = NULL, *chosen_s_to_c_mac = NULL;
  char *chosen_c_to_s_compression = NULL, *chosen_s_to_c_compression = NULL;
  SshBuffer *client_kexinit, *server_kexinit;

  SSH_DEBUG(5, ("ssh_tr_negotiate"));
  
  /* We must have both kexinit packets available. */
  assert(tr->client_kexinit_packet != NULL);
  assert(tr->server_kexinit_packet != NULL);

  /* Copy the kexinit packets into local buffers. */
  client_kexinit = ssh_buffer_allocate();
  ssh_buffer_append(client_kexinit, ssh_buffer_ptr(tr->client_kexinit_packet),
                ssh_buffer_len(tr->client_kexinit_packet));
  server_kexinit = ssh_buffer_allocate();
  ssh_buffer_append(server_kexinit, ssh_buffer_ptr(tr->server_kexinit_packet),
                ssh_buffer_len(tr->server_kexinit_packet));

  /* Parse relevant information from the client packet. */
  if (ssh_decode_buffer(client_kexinit,
                        SSH_FORMAT_CHAR, NULL,
                        SSH_FORMAT_DATA, NULL, 16,
                        SSH_FORMAT_UINT32_STR, &client_kex, NULL,
                        SSH_FORMAT_UINT32_STR, &client_server_host_key, NULL,
                        SSH_FORMAT_END) == 0)
    return FALSE;

  /* Parse the same information from the server packet. */
  if (ssh_decode_buffer(server_kexinit,
                        SSH_FORMAT_CHAR, NULL,
                        SSH_FORMAT_DATA, NULL, 16,
                        SSH_FORMAT_UINT32_STR, &server_kex, NULL,
                        SSH_FORMAT_UINT32_STR, &server_server_host_key, NULL,
                        SSH_FORMAT_END) == 0)
    {
      ssh_xfree(client_kex);
      ssh_xfree(client_server_host_key);
      return FALSE;
    }

  /* The kex method will have to be supported by both. */
  common_kex = ssh_name_list_intersection(client_kex, server_kex);
  ssh_xfree(client_kex);
  ssh_xfree(server_kex);

  /* Compute which host key types are supported by both. */
  common_host_key = ssh_name_list_intersection(client_server_host_key,
                                               server_server_host_key);

  tr->host_key_names = ssh_xstrdup(common_host_key);

  ssh_xfree(client_server_host_key);
  ssh_xfree(server_server_host_key);
  
  /* Loop over the common kex methods. */
  chosen_host_key = NULL;
  for (kex = strtok(common_kex, ","); kex; kex = strtok(NULL, ","))
    {
      char *host_key_copy = ssh_xstrdup(common_host_key);
      char *hk;

      for (hk = strtok(host_key_copy, ","); hk; hk = strtok(NULL, ","))
        {
          /* XXX if hk does not support signature/encryption as needed by kex,
             then continue. */
          
          chosen_kex = ssh_xstrdup(kex);
          chosen_host_key = ssh_xstrdup(hk);
          break;
        }
      ssh_xfree(host_key_copy);
      if (chosen_host_key != NULL)
        break;
    }
  ssh_xfree(common_kex);
  ssh_xfree(common_host_key);
  if (chosen_kex == NULL)
    {
      /* Failed to find acceptable kex method. */
      ssh_buffer_free(client_kexinit);
      ssh_buffer_free(server_kexinit);
      return FALSE;
    }

  /* Choose the remaining algorithms. */
  chosen_c_to_s_cipher = ssh_tr_negotiate_one_alg(tr, "c_to_s_cipher",
                                                  client_kexinit,
                                                  server_kexinit);
  chosen_s_to_c_cipher = ssh_tr_negotiate_one_alg(tr, "s_to_c_cipher",
                                                  client_kexinit,
                                                  server_kexinit);
  chosen_c_to_s_mac = ssh_tr_negotiate_one_alg(tr, "c_to_s_mac",
                                               client_kexinit,
                                               server_kexinit);
  chosen_s_to_c_mac = ssh_tr_negotiate_one_alg(tr, "s_to_c_mac",
                                               client_kexinit,
                                               server_kexinit);
  chosen_c_to_s_compression = ssh_tr_negotiate_one_alg(tr, "c_to_s_compr",
                                                       client_kexinit,
                                                       server_kexinit);
  chosen_s_to_c_compression = ssh_tr_negotiate_one_alg(tr, "s_to_c_compr",
                                                       client_kexinit,
                                                       server_kexinit);
  
  ssh_buffer_free(client_kexinit);
  ssh_buffer_free(server_kexinit);

  if (!chosen_c_to_s_cipher || !chosen_s_to_c_cipher ||
      !chosen_c_to_s_mac || !chosen_s_to_c_mac ||
      !chosen_c_to_s_compression || !chosen_s_to_c_compression)
    {
      /* Failed to agree on some algorithm. */

      ssh_xfree(chosen_c_to_s_cipher);
      ssh_xfree(chosen_s_to_c_cipher);
      ssh_xfree(chosen_c_to_s_mac);
      ssh_xfree(chosen_s_to_c_mac);
      ssh_xfree(chosen_c_to_s_compression);
      ssh_xfree(chosen_kex);
      ssh_xfree(chosen_host_key);
      return FALSE;
    }

  /* Determine whether the guessed algorithm was wrong. */
  *guess_was_wrong = (strcmp(chosen_kex, tr->guessed_kex) != 0 ||
                      strcmp(chosen_host_key, tr->guessed_host_key) != 0);

  /* Set the selected algorithms. */
  ssh_tr_set_string(&tr->kex_name, chosen_kex);
  ssh_tr_set_string(&tr->host_key_name, chosen_host_key);
  ssh_tr_set_string(&tr->c_to_s.cipher_name, chosen_c_to_s_cipher);
  ssh_tr_set_string(&tr->s_to_c.cipher_name, chosen_s_to_c_cipher);
  ssh_tr_set_string(&tr->c_to_s.mac_name, chosen_c_to_s_mac);
  ssh_tr_set_string(&tr->s_to_c.mac_name, chosen_s_to_c_mac);
  ssh_tr_set_string(&tr->c_to_s.compression_name,
                    chosen_c_to_s_compression);
  ssh_tr_set_string(&tr->s_to_c.compression_name,
                    chosen_s_to_c_compression);

#if 0
  ssh_debug("c_to_s: cipher %s, mac %s, compression %s",
        chosen_c_to_s_cipher, chosen_c_to_s_mac, chosen_c_to_s_compression);
  ssh_debug("s_to_c: cipher %s, mac %s, compression %s",
        chosen_s_to_c_cipher, chosen_s_to_c_mac, chosen_s_to_c_compression);
#endif
  
  /* Set the current kex method and hash handles (cipher, mac, and compression
     aren't changed until NEWKEYS is sent or received). */
  tr->kex = ssh_kex_lookup(chosen_kex);
  if (tr->kex == NULL)
    {
      ssh_fatal("ssh_tr_negotiate: chosen kex '%.100s' not found.",
                chosen_kex);  
    }
      
  tr->hash = ssh_kex_allocate_hash(chosen_kex);
  if (tr->hash == NULL)
    {
      ssh_fatal("unable to allocate the hash function needed by the "
                "key exchange method %s.", chosen_kex);
    }
  
  /* Update guesses so that the next key exchange will use the current
     algorithms as the guess. */
  ssh_tr_set_string(&tr->guessed_kex, ssh_xstrdup(chosen_kex));
  ssh_tr_set_string(&tr->guessed_host_key, ssh_xstrdup(chosen_host_key));
  
  /* Indicate that negotiation was successful. */
  return TRUE;
}

/* Gets the packet type from the buffer, without removing it.  The buffer
   should contain the packet payload. */

unsigned int ssh_tr_peek_packet_type(SshBuffer *packet)
{
  return (unsigned int) (ssh_buffer_ptr(packet))[0];
}

/* Processes a received SSH_MSG_DISCONNECT packet.  Does not free the
   buffer. */

void ssh_tr_input_disconnect(SshTransportCommon tr, SshBuffer *packet)
{
  unsigned int packet_type;
  SshUInt32 reason;
  char *message;

  SSH_DEBUG(5, ("ssh_tr_input_disconnect"));

  if (ssh_decode_buffer(packet,
                        SSH_FORMAT_CHAR, &packet_type,
                        SSH_FORMAT_UINT32, &reason,
                        SSH_FORMAT_UINT32_STR, &message, NULL,
                        SSH_FORMAT_UINT32_STR, NULL, NULL, /* language tag */
                        SSH_FORMAT_END) == 0)
    {
      ssh_debug("ssh_tr_input_disconnect: bad DISCONNECT");
      return;
    }
  if (packet_type != SSH_MSG_DISCONNECT)
    ssh_fatal("ssh_tr_input_disconnect: non-DISCONNECT packet %d",
              packet_type);
  ssh_tr_up_disconnect(tr, FALSE, FALSE, reason, "%.300s", message);
  ssh_xfree(message);
}

/* Processes a received SSH_MSG_DEBUG packet.  Does not free the
   buffer. */

void ssh_tr_input_debug(SshTransportCommon tr, SshBuffer *packet)
{
  unsigned int packet_type;
  char *message, *language;
  SshBuffer buffer;
  Boolean always_display;

  SSH_DEBUG(5, ("ssh_tr_input_debug"));

  if (ssh_decode_buffer(packet,
                        SSH_FORMAT_CHAR, &packet_type,
                        SSH_FORMAT_BOOLEAN, &always_display,
                        SSH_FORMAT_UINT32_STR, &message, NULL,
                        SSH_FORMAT_UINT32_STR, &language, NULL,
                        SSH_FORMAT_END) == 0)
    {
      ssh_debug("ssh_tr_input_debug: bad DEBUG message");
      return;
    }
  if (packet_type != SSH_MSG_DEBUG)
    ssh_fatal("ssh_tr_input_disconnect: non-DEBUG packet %d",
              packet_type);

  ssh_buffer_init(&buffer);
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_BOOLEAN, always_display,
                    SSH_FORMAT_UINT32_STR, message, strlen(message),
                    SSH_FORMAT_UINT32_STR, language, strlen(language),
                    SSH_FORMAT_END);
  ssh_tr_up_send(tr, SSH_CROSS_DEBUG, ssh_buffer_ptr(&buffer),
                 ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
  ssh_xfree(message);
  ssh_xfree(language);
}

/* Tries to read packet data from the connection.  If a complete packet has
   been received, returns the packet payload in a buffer.  The caller is
   responsible for freeing the buffer with ssh_buffer_free().  Otherwise,
   this returns NULL.  If an error is received (such as EOF or a corrupted
   packet), this returns NULL and calls ssh_tr_up_disconnect() to
   pass the error to upper levels. */

SshBuffer *ssh_tr_input_packet(SshTransportCommon tr)
{
  int len;
  unsigned int mac_len, pad_len, packet_type;
  unsigned char mac[SSH_MAX_HASH_DIGEST_LENGTH];
  SshBuffer *packet;
  unsigned char *cp;
  unsigned char seq_buf[4];
  
  SSH_DEBUG(5, ("ssh_tr_input_packet"));

restart:

  packet = tr->incoming_packet;
  
  /* Allocate a packet buffer if appropriate. */
  if (packet == NULL)
    {
      packet = ssh_buffer_allocate(); /* This is a possible leak. XXX */
      tr->incoming_packet = packet;
      tr->incoming_packet_index = 0;
      tr->incoming_packet_len = 0;
      /* Reserve space for the initial 8 bytes. */
      ssh_buffer_append_space(packet, &cp, tr->incoming_granularity);
    }
  assert(ssh_buffer_len(packet) >= tr->incoming_granularity);

  /* Read packet length if it has not yet been received. */
  while (tr->incoming_packet_index < tr->incoming_granularity)
    {
      len = ssh_stream_read(tr->connection,
                            ssh_buffer_ptr(packet) + tr->incoming_packet_index,
                            tr->incoming_granularity -
                            tr->incoming_packet_index);
      SSH_DEBUG(5, ("ssh_tr_input_packet: read %d bytes", len));
      if (len < 0)
        return NULL;  /* No more data available at this time. */
      if (len == 0)
        {
          /* Received EOF. */
          SSH_DEBUG(5, ("received eof"));
          if (tr->incoming_packet_index == 0)
            { /* Clean EOF at beginning of packet. */
              tr->up_outgoing_eof = TRUE;
              tr->received_state = RECEIVED_DEAD;
              ssh_tr_up_signal_input(tr);
            }
          else
            ssh_tr_up_disconnect(tr, TRUE, FALSE,
                                 SSH_DISCONNECT_CONNECTION_LOST,
                                 "Connection lost.");
          return NULL;
        }
      tr->incoming_packet_index += len;
    }

  /* Cache the length of incoming MAC. */
  mac_len = ssh_mac_length(tr->incoming_mac);
  
  /* Decrypt and retrieve packet length if it hasn't already been done. */

  if (tr->incoming_packet_len == 0)
    {
      /* Decrypt the first few bytes of the incoming packet. */
      if (ssh_cipher_transform(tr->incoming_cipher, ssh_buffer_ptr(packet),
                               ssh_buffer_ptr(packet),
                               tr->incoming_granularity) != SSH_CRYPTO_OK)
        ssh_fatal("ssh_tr_input_packet: decrypting length failed (gran %d)",
                  tr->incoming_granularity);
  
      /* Compute the total length of the packet. */

      tr->incoming_packet_len = SSH_GET_32BIT(ssh_buffer_ptr(packet)) + mac_len + 4;

      /* Sanity check the length. */
      if (tr->incoming_packet_len > SSH_MAX_TOTAL_PACKET_LENGTH)
        {
          /* Send a disconnect packet to the other side. */
          ssh_tr_up_disconnect(tr, TRUE, TRUE,
                               SSH_DISCONNECT_PROTOCOL_ERROR,
                               "Protocol error: packet too long: %d.",
                               tr->incoming_packet_len);
          tr->incoming_packet_len = 0; /* Just in case... */
          return NULL;
        }

      /* Reserve space for the entire packet. */
      ssh_buffer_append_space(packet, &cp,
                          tr->incoming_packet_len - ssh_buffer_len(packet));
    }

  /* Keep reading until the entire packet has been received. */
  while (tr->incoming_packet_index < tr->incoming_packet_len)
    {
      len = ssh_stream_read(tr->connection,
                            ssh_buffer_ptr(packet) + tr->incoming_packet_index,
                            tr->incoming_packet_len -
                            tr->incoming_packet_index);
      SSH_DEBUG(5, ("ssh_tr_input_packet: read %d bytes", len));
      if (len < 0)
        return NULL;  /* No more data available at this time. */
      if (len == 0)
        {
          /* Received EOF. */
          ssh_tr_up_disconnect(tr, TRUE, FALSE,
                               SSH_DISCONNECT_CONNECTION_LOST,
                               "Connection lost.");
          return NULL;
        }
      tr->incoming_packet_index += len;
    }

#ifdef DUMP_PACKETS
  ssh_debug("Dumping incoming...");
  buffer_dump(packet);
#endif /* DUMP_PACKETS */
  
  /* All of the packet has now been received.  */
  if ((tr->incoming_packet_len - mac_len) % tr->incoming_granularity != 0)
    {
      ssh_tr_up_disconnect(tr, TRUE, FALSE, SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Received packet with wrong granularity.");
      return NULL;
    }
  
  /* Decrypt the rest of the packet (the first cipher block has already been
     decrypted). */

  if (ssh_cipher_transform(tr->incoming_cipher,
                           ssh_buffer_ptr(packet) + tr->incoming_granularity,
                           ssh_buffer_ptr(packet) + tr->incoming_granularity,
                           tr->incoming_packet_len -
                           tr->incoming_granularity - mac_len)
      != SSH_CRYPTO_OK)
    ssh_fatal("ssh_tr_input_packet: decrypting rest failed (len %d gran %d mac %d)",
          tr->incoming_packet_len, tr->incoming_granularity, mac_len);

  /* Verify MAC. */

  switch (tr->ssh_old_mac_bug_compat)
    {
    case FALSE: /* Everything is a-ok */
      ssh_mac_start(tr->incoming_mac);
      SSH_PUT_32BIT(seq_buf, tr->incoming_sequence_number);
      ssh_mac_update(tr->incoming_mac, seq_buf, 4);
      ssh_mac_update(tr->incoming_mac, ssh_buffer_ptr(packet),
                       tr->incoming_packet_len - mac_len);
      ssh_mac_final(tr->incoming_mac, mac);
      break;
    case TRUE: /* other side counts the MAC in the old (==wrong) way. */
      ssh_mac_start(tr->incoming_mac);
      ssh_mac_update(tr->incoming_mac, ssh_buffer_ptr(packet),
                     tr->incoming_packet_len - mac_len);
      SSH_PUT_32BIT(seq_buf, tr->incoming_sequence_number);
      ssh_mac_update(tr->incoming_mac, seq_buf, 4);
      ssh_mac_final(tr->incoming_mac, mac);
      break;
    default:
      ssh_fatal("ssh_tr_input_packet: Whoah! How can a Boolean value be"
                " something else than TRUE or FALSE?");
    }

  if (memcmp(mac, ssh_buffer_ptr(packet) + tr->incoming_packet_len - mac_len,
             mac_len) != 0)
    {

      /* MAC fails. */

      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_MAC_ERROR,
                           "Message authentication check fails.");
      return NULL;
    }

  /* MAC ok.  Remove the MAC from the packet. */
  ssh_buffer_consume_end(packet, mac_len);

  if (ssh_decode_buffer(packet,
                        SSH_FORMAT_UINT32, NULL,
                        SSH_FORMAT_CHAR, &pad_len,
                        SSH_FORMAT_END) == 0)
    {
      ssh_tr_up_disconnect(tr, TRUE, TRUE, SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Badly formatted packet");
      return NULL;
    }
  if (pad_len > ssh_buffer_len(packet))
    {
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Bad padding length %d", pad_len);
      return NULL;
    }
  ssh_buffer_consume_end(packet, pad_len);
  /* At this point, the buffer contains the (possibly compressed) payload. */
  
  /* Uncompress the payload if appropriate. */
  tr->compressed_incoming_bytes += ssh_buffer_len(packet);
  if (!ssh_compress_is_none(tr->compression_incoming))
    {
      SshBuffer *aux_packet;

      /* Uncompress the data. */
      ssh_buffer_clear(tr->compression_buffer);
      ssh_compress_buffer(tr->compression_incoming, ssh_buffer_ptr(packet),
                            ssh_buffer_len(packet), tr->compression_buffer);

      /* Swap the buffers so that uncompressed data is returned.  We'll reuse
         the other buffer for compression later. */
      aux_packet = tr->compression_buffer;
      tr->compression_buffer = packet;
      packet = aux_packet;
    }
  tr->uncompressed_incoming_bytes += ssh_buffer_len(packet);

  /* Update packet sequence number. */
  tr->incoming_sequence_number++;
  
  /* Return the payload.  The caller will free the packet. */

  tr->incoming_packet = NULL;

#ifdef DUMP_PACKETS
  ssh_debug("-- decrypted --");
  buffer_dump(packet);
#endif /* DUMP_PACKETS */

  /* Check for SSH_MSG_IGNORE packets. */
  packet_type = ssh_tr_peek_packet_type(packet);
  switch (packet_type)
    {
    case SSH_MSG_IGNORE:      /* These packets are immediately ignored. */
      ssh_buffer_free(packet);
      goto restart;

    case SSH_MSG_DISCONNECT:  /* The other side is disconnecting. */
      ssh_tr_input_disconnect(tr, packet);
      ssh_buffer_free(packet);
      return NULL;

    case SSH_MSG_DEBUG:       /* The other side sends a debug packet. */
      ssh_tr_input_debug(tr, packet);
      ssh_buffer_free(packet);
      return NULL;
      
    case SSH_MSG_UNIMPLEMENTED: /* Strange, our packet was unimplemented? */
      ssh_debug("Strange, other side indicates our message as unimplemented.");
      ssh_buffer_free(packet);
      return NULL;
      
    default:
      /* Other packet types are processed normally. */
      break;
    }

  /* Return the packet for normal processing. */
  return packet;
}

Boolean ssh_tr_process_received_kexinit(SshTransportCommon tr,
                                        SshBuffer *packet)
{
  Boolean guess_was_wrong;

  SSH_DEBUG(5, ("ssh_tr_process_received_kexinit"));

  /* Save the kexinit packet. */
  if (tr->server)
    {
      assert(tr->client_kexinit_packet == NULL);
      tr->client_kexinit_packet = packet;
    }
  else
    {
      assert(tr->server_kexinit_packet == NULL);
      tr->server_kexinit_packet = packet;
    }

  /* Perform algorithm negotiation computations based on the two kex
     packets. */
  if (!ssh_tr_negotiate(tr, &guess_was_wrong))
    {
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                           "Algorithm negotiation failed.");
      return FALSE;
    }

  if (guess_was_wrong)
    tr->received_state = RECEIVED_KEXINIT;
  else
    {
      /* If we aren't expecting to receive kex1, go directly to expecting
         kex2. */
      if ((tr->server ? tr->kex->server_input_kex1 :
           tr->kex->client_input_kex1)
          == NULL)
        tr->received_state = RECEIVED_KEX1_FINAL;
      else
        tr->received_state = RECEIVED_KEX1_IGNORED;
    }
  
  assert(tr->sent_state == SENT_KEXINIT);
  if (guess_was_wrong)
    {
      /* Resend our KEX1 packet, if we are to send one. */
      packet = ssh_tr_make_kex1(tr);
      if (packet)
        {
          ssh_tr_send_packet(tr, ssh_buffer_ptr(packet),
                             ssh_buffer_len(packet));
          /* Note that the packet has been saved for key negotiation, and
             cannot be freed here. */
        }
    }

  tr->sent_state = SENT_KEX1_FINAL;

  return TRUE;
}

/* Receives a kexinit packet from the remote host.  Returns TRUE if
   reading should continue. */

Boolean ssh_tr_input_kexinit(SshTransportCommon tr)
{
  int packet_type;
  SshBuffer *packet;

  SSH_DEBUG(5, ("ssh_tr_input_kexinit"));
  
  /* If we haven't sent our kexinit yet, do nothing (the send will
     probably just involve buffering, and should happen fast).  This simplifies
     code below, since we can now always perform negotiation in this
     function. */
  if (tr->sent_state < SENT_KEXINIT)
    return FALSE;
  
  /* Read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;

  /* If we have requested rekey, we might get here with any normal data
     packet until the other side responds with a KEXINIT packet.  If the packet
     is a data packet, and doing rekey, we process it as a normal packet. */
  
  /* Check that the packet type is KEXINIT. */
  packet_type = ssh_tr_peek_packet_type(packet);
  if (packet_type != SSH_MSG_KEXINIT)
    {
      ssh_buffer_free(packet);
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Received packet type %d expecting KEXINIT",
                           (int)packet_type);
      return FALSE;
    }

  /* Process the received packet now.  This code is shared with rekey. */
  return ssh_tr_process_received_kexinit(tr, packet);
}

/* Send a packet containing only the packet type.  This does not update
   state. */

void ssh_tr_send_simple_packet(SshTransportCommon tr,
                               unsigned int packet_type)
{
  SshBuffer buffer;

  SSH_DEBUG(5, ("ssh_tr_send_simple_packet %d", packet_type));
  
  ssh_buffer_init(&buffer);
  buffer_put_char(&buffer, packet_type);
  ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer),
                     ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
}

/* Takes the new encryption keys into use for one direction.  This clears
   the keys from memory after they have been set. */
    
void ssh_tr_set_keys(SshTransportCommon tr, struct SideKexInfo *info,
                     size_t *granularityp, Boolean is_outgoing,
                     SshCipher *cipherp, SshMac *macp,
                     SshCompression *compressionp)
{
  size_t key_len;

  SSH_DEBUG(5, ("ssh_tr_set_keys"));
  
  /* Set encryption algorithm. */

  if (*cipherp)
    ssh_cipher_free(*cipherp);
    
  key_len = ssh_cipher_get_key_length(info->cipher_name);
  if (key_len == 0)
    {
      if ((strcasecmp("twofish", info->cipher_name) == 0) ||
          (strncasecmp("twofish-", info->cipher_name, 8) == 0))
        key_len = 32;  /* Twofish uses 256 bit key. */
      else
        key_len = 16;  /* Default is 128 bits if variable length keys. */
    }
  assert(key_len <= sizeof(info->encryption_key));

  if (ssh_cipher_allocate(info->cipher_name, info->encryption_key, key_len,
                          is_outgoing, cipherp) != SSH_CRYPTO_OK)
    ssh_fatal("ssh_tr_set_keys: cipher init failed: %.100s",
              info->cipher_name);
  *granularityp = ssh_cipher_get_block_length(*cipherp);
  if (*granularityp < 8)
    *granularityp = 8;
  
  /* Set iv.  We intentionally ignore the return status in case stream
     ciphers return an error. */
  ssh_cipher_set_iv(*cipherp, info->iv);

  /* Set mac algorithm. */
  if (*macp)
    ssh_mac_free(*macp);

  /* XXX macs with key length != 16 */

  if (ssh_mac_allocate(info->mac_name, info->integrity_key, 16,
                       macp) != SSH_CRYPTO_OK)
    ssh_fatal("ssh_tr_set_keys: mac init failed: %.100s", info->mac_name);

  /* Set compression algorithm.  First we free any old compression state. */
  if (*compressionp)
    ssh_compress_free(*compressionp);
  *compressionp = ssh_compress_allocate(info->compression_name, is_outgoing);
  if (!*compressionp)
    ssh_fatal("ssh_tr_set_keys: compression init failed: %.100s",
              info->compression_name);

  /* Clear the keys from memory. */
  memset(info->encryption_key, 0, sizeof(info->encryption_key));
  memset(info->iv, 0, sizeof(info->iv));
  memset(info->integrity_key, 0, sizeof(info->integrity_key));
}

/* Called when the validity check for the received host key is complete.
   If the validity check failed, this disconnects; otherwise this proceeds
   with the key exchange. */

void ssh_tr_key_check_done(Boolean result, void *context)
{
  SshTransportCommon tr = context;
  SshBuffer *packet;

  SSH_DEBUG(5, ("ssh_tr_key_check_done"));
  
  assert(tr->received_state == RECEIVED_KEY_CHECK);

  if (!result)
    {
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
                           "Could not ascertain validity of host key.");
      return;
    }
  
  /* The host key has been accepted. */

  /* Send a KEX2 packet in response, if appropriate.  This will use data
     from the received KEX1 packet, if any. */
  packet = ssh_tr_make_kex2(tr);
  if (packet)
    {
      ssh_tr_send_packet(tr, ssh_buffer_ptr(packet),
                         ssh_buffer_len(packet));
      /* Note that KEX2 packets are not saved anywhere and need to be freed
         here. */
      ssh_buffer_free(packet);
    } 

  /* Send a NEWKEYS packet. */
  ssh_tr_send_simple_packet(tr, SSH_MSG_NEWKEYS);
  tr->sent_state = SENT_NEWKEYS;
  
  /* Take the new keys and algorithms into use. */
  if (tr->server)
    ssh_tr_set_keys(tr, &tr->s_to_c, &tr->outgoing_granularity, TRUE,
                    &tr->outgoing_cipher, &tr->outgoing_mac,
                    &tr->compression_outgoing);
  else
    ssh_tr_set_keys(tr, &tr->c_to_s, &tr->outgoing_granularity, TRUE,
                    &tr->outgoing_cipher, &tr->outgoing_mac,
                    &tr->compression_outgoing);

  /* Go directly to expecting newkeys if not expecting to receive KEX2. */
  if ((tr->server ? tr->kex->server_input_kex2 : tr->kex->client_input_kex2)
      == NULL)
    tr->received_state = RECEIVED_KEX2;
  else
    tr->received_state = RECEIVED_KEX1_FINAL;

  ssh_tr_process_output(tr);
  ssh_tr_wake_up_input(tr);
}

/* Receive a kex1 packet.  If appropriate, send kex2 in response.
   Returns TRUE if processing should continue, and FALSE if there is
   nothing more to do. */

Boolean ssh_tr_input_kex1(SshTransportCommon tr)
{
  SshBuffer *packet;
  Boolean result;

  SSH_DEBUG(5, ("ssh_tr_input_kex1"));
  
  /* Don't proceed until we have sent our own final KEX1 packet.  This
     simplifies the code. */
  if (tr->sent_state < SENT_KEX1_FINAL)
    return FALSE;
  
  /* Read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;

  /* Ignore the kex1 packet if appropriate. */
  if (tr->received_state == RECEIVED_KEXINIT)
    {
      /* We are receiving a kex1 packet that needs to be ignored. */
      ssh_buffer_free(packet);
      /* If we aren't expecting to receive kex1, go directly to expecting
         kex2. */
      if ((tr->server ? tr->kex->server_input_kex1 :
           tr->kex->client_input_kex1)
          == NULL)
        tr->received_state = RECEIVED_KEX1_FINAL;
      else
        tr->received_state = RECEIVED_KEX1_IGNORED;
      return TRUE;
    }

  /* Save the received KEX1 packet. */
  if (tr->server)
    result = (*tr->kex->server_input_kex1)(tr, packet);
  else
    result = (*tr->kex->client_input_kex1)(tr, packet);

  if (!result)
    {
      ssh_buffer_free(packet);
      return FALSE;  /* Parsing failed. */
    }
  
  /* Mark that we are processing key check. */
  tr->received_state = RECEIVED_KEY_CHECK;

  if (tr->key_check)
    (*tr->key_check)(tr->server_host_name,
                     ssh_buffer_ptr(tr->public_host_key_blob),
                     ssh_buffer_len(tr->public_host_key_blob),
                     ssh_tr_key_check_done,
                     (void *)tr,
                     tr->key_check_context);
  else
    ssh_tr_key_check_done(TRUE, (void *)tr);

  ssh_buffer_free(packet);
  return TRUE;
}

/* Forward declaration. */
void ssh_tr_input_kex2_finalize(SshTransportCommon tr);

/* Process KEX2 packet.  If no packet is yet available, return. Rest
   is done ssh_tr_input_kex2_finalize(), after key check.  */
void ssh_tr_input_kex2(SshTransportCommon tr)
{
  SshBuffer *packet;

  SSH_DEBUG(5, ("ssh_tr_input_kex2"));
  
  /* Read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return;

  /* Process the packet to finalize our part of the key exchange.
     This will also free the packet. */
  if (tr->server)
    (*tr->kex->server_input_kex2)(tr, packet,
                                  ssh_tr_input_kex2_finalize);
  else
    (*tr->kex->client_input_kex2)(tr, packet,
                                  ssh_tr_input_kex2_finalize);
  
}

/* If key exchange fails, initiate disconnect and return.  If KEX2 is
   successfully received and the key exchange successfully completes,
   update state and send NEWKEYS. After these, this calls
   ssh_tr_process_input() to continue the protocol. */
void ssh_tr_input_kex2_finalize(SshTransportCommon tr)
{
  Boolean success;

  success = tr->key_check_result;
  
  if (!success)
    {
      /* Disconnect. */
      ssh_tr_up_disconnect(tr, TRUE, TRUE, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                           "Key exchange failed.");
      return;
    }
  
  /* Key exchange has been successful.  Send newkeys. */
  ssh_tr_send_simple_packet(tr, SSH_MSG_NEWKEYS);
  
  /* Take the new keys and algorithms into use. */
  if (tr->server)
    ssh_tr_set_keys(tr, &tr->s_to_c, &tr->outgoing_granularity, TRUE,
                    &tr->outgoing_cipher, &tr->outgoing_mac,
                    &tr->compression_outgoing);
  else
    ssh_tr_set_keys(tr, &tr->c_to_s, &tr->outgoing_granularity, TRUE,
                    &tr->outgoing_cipher, &tr->outgoing_mac,
                    &tr->compression_outgoing);

  /* Update state. */
  tr->sent_state = SENT_NEWKEYS;
  tr->received_state = RECEIVED_KEX2;
  ssh_tr_process_output(tr);
  
  ssh_tr_process_input(tr);
}
  
/* Process NEWKEYS packet.  This will cause new algorithms to be taken
   into use for incoming packets. */

Boolean ssh_tr_input_newkeys(SshTransportCommon tr)
{
  SshBuffer *packet;
  unsigned int packet_type;

  SSH_DEBUG(5, ("ssh_tr_input_newkeys"));
  
  /* Read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;
  packet_type = ssh_tr_peek_packet_type(packet);
  if (packet_type != SSH_MSG_NEWKEYS)
    {
      ssh_tr_up_disconnect(tr, TRUE, TRUE, SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Protocol error: Received %d as newkeys",
                           packet_type);
      return FALSE;
    }
  ssh_buffer_free(packet);
  
  if (tr->server)
    ssh_tr_set_keys(tr, &tr->c_to_s, &tr->incoming_granularity, FALSE,
                    &tr->incoming_cipher, &tr->incoming_mac,
                    &tr->compression_incoming);
  else
    ssh_tr_set_keys(tr, &tr->s_to_c, &tr->incoming_granularity, FALSE,
                    &tr->incoming_cipher, &tr->incoming_mac,
                    &tr->compression_incoming);

  /* Mark that we have received NEWKEYS. */
  tr->received_state = RECEIVED_NEWKEYS;

  return TRUE;
}

/* Send a SSH_CROSS_STARTUP packet upstream. */

void ssh_tr_up_send_startup(SshTransportCommon tr)
{
  SshBuffer buffer;
  char buf[100];

  SSH_DEBUG(5, ("ssh_tr_up_send_startup"));
  
  ssh_buffer_init(&buffer);
  buffer_put_uint32_string(&buffer, SSH_CROSS_LAYER_VERSION,
                           strlen(SSH_CROSS_LAYER_VERSION));
  buffer_put_uint32_string(&buffer, tr->session_identifier,
                           tr->session_identifier_len);
  buffer_put_uint32_string(&buffer, tr->remote_version,
                           strlen(tr->remote_version));
  if (ssh_tcp_get_remote_address(tr->connection, buf, sizeof(buf)))
    buffer_put_uint32_string(&buffer, buf, strlen(buf));
  else
    buffer_put_uint32_string(&buffer, NULL, 0);
  if (ssh_tcp_get_remote_port(tr->connection, buf, sizeof(buf)))
    buffer_put_uint32_string(&buffer, buf, strlen(buf));
  else
    buffer_put_uint32_string(&buffer, NULL, 0);
  ssh_tr_up_send(tr, SSH_CROSS_STARTUP,
                 ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);

  /* Mix the session identifier into our random number generator.  The
     session identifier depends on the entire key exchange (every bit
     of it).  It thus combines entropy from both the local machine and
     the remote host.  Some of the entropy is secret to an outsider
     (e.g., the secret session key).  The random state can be used to
     update the random seed file later. */
  ssh_random_add_noise(tr->random_state, tr->session_identifier,
                       tr->session_identifier_len);
  ssh_random_stir(tr->random_state);
}

/* Send a SSH_CROSS_ALGORITHMS packet upstream. */

void ssh_tr_up_send_algorithms(SshTransportCommon tr)
{
  SshBuffer buffer;

  SSH_DEBUG(5, ("ssh_tr_up_send_algorithms"));
  
  assert(tr->public_host_key_blob != NULL);

  ssh_buffer_init(&buffer);
  buffer_put_uint32_string(&buffer, tr->kex_name, strlen(tr->kex_name));
  buffer_put_uint32_string(&buffer, tr->host_key_name,
                           strlen(tr->host_key_name));
  buffer_put_uint32_string(&buffer, ssh_buffer_ptr(tr->public_host_key_blob),
                           ssh_buffer_len(tr->public_host_key_blob));
  buffer_put_uint32_string(&buffer, tr->c_to_s.cipher_name,
                           strlen(tr->c_to_s.cipher_name));
  buffer_put_uint32_string(&buffer, tr->s_to_c.cipher_name,
                           strlen(tr->s_to_c.cipher_name));
  buffer_put_uint32_string(&buffer, tr->c_to_s.mac_name,
                           strlen(tr->c_to_s.mac_name));
  buffer_put_uint32_string(&buffer, tr->s_to_c.mac_name,
                           strlen(tr->s_to_c.mac_name));
  buffer_put_uint32_string(&buffer, tr->c_to_s.compression_name,
                           strlen(tr->c_to_s.compression_name));
  buffer_put_uint32_string(&buffer, tr->s_to_c.compression_name,
                           strlen(tr->s_to_c.compression_name));
  ssh_tr_up_send(tr, SSH_CROSS_ALGORITHMS,
                 ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
}

/* Try to receive a service request packet.  If received, call the
   application callback to determine whether the service can be accepted.
   If the service is denied, send disconnect and destroy this context.
   If the service is accepted, send a service accept packet, and enter
   interactive mode. */

Boolean ssh_tr_input_service_request(SshTransportCommon tr)
{
  SshBuffer *packet, buffer;
  unsigned int packet_type;

  SSH_DEBUG(5, ("ssh_tr_input_service_request"));
  
  /* Try to read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;

  if (ssh_decode_buffer(packet,
                        SSH_FORMAT_CHAR, &packet_type,
                        SSH_FORMAT_UINT32_STR, &tr->service_name, NULL,
                        SSH_FORMAT_END) == 0 ||
      packet_type != SSH_MSG_SERVICE_REQUEST)
    {
      /* We shouldn't have received this here.  This is a protocol error. */
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Protocol error: bad service request %d",
                           packet_type);
      return FALSE;
    }
  
  /* Free the packet. */
  ssh_buffer_free(packet);

  /* Send the service request upstream. */
  ssh_buffer_init(&buffer);
  buffer_put_uint32_string(&buffer, tr->service_name,
                           strlen(tr->service_name));
  ssh_tr_up_send(tr, SSH_CROSS_SERVICE_REQUEST,
                 ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);

  tr->received_state = RECEIVED_SERVICE_REQUEST;

  return TRUE;
}

/* Try to receive a service accept packet.  Advance to interactive state
   when received. */

Boolean ssh_tr_input_service_accept(SshTransportCommon tr)
{
  SshBuffer *packet;
  unsigned int packet_type;

  SSH_DEBUG(5, ("ssh_tr_input_service_accept"));
  
  /* Try to read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;

  /* Check that it is a service accept packet. */
  if (ssh_decode_buffer(packet,
                        SSH_FORMAT_CHAR, &packet_type,
                        SSH_FORMAT_END) == 0 ||
      packet_type != SSH_MSG_SERVICE_ACCEPT)
    {
      /* We shouldn't have received this here.  This is a protocol error. */
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Protocol error: bad service accept %d",
                           packet_type);
      return FALSE;
    }

  /* Free the packet. */
  ssh_buffer_free(packet);

  /* Send a SSH_CROSS_STARTUP message upwards. */
  ssh_tr_up_send_startup(tr);

  /* Send a SSH_CROSS_ALGORITHMS packet upwards. */
  ssh_tr_up_send_algorithms(tr);
  
  /* Update state. */
  tr->received_state = RECEIVED_INTERACTIVE;

  /* Process output, so that we get advanced from the service request state
     if we are still lingering there. */
  ssh_tr_process_output(tr);

  return TRUE;
}

/* Constructs and sends an outgoing KEXINIT packet with the explicitly
   given algorithms.  This does not update state. */

void ssh_tr_output_kexinit_explicit(SshTransportCommon tr,
                                    const char *ciphers_c_to_s,
                                    const char *ciphers_s_to_c,
                                    const char *macs_c_to_s,
                                    const char *macs_s_to_c,
                                    const char *compressions_c_to_s,
                                    const char *compressions_s_to_c,
                                    const char *host_key_algorithms)
{
  int i;
  SshBuffer *packet, *kex1_packet;
  char *cp, *cp2;

  SSH_DEBUG(5, ("ssh_tr_output_kexinit"));
  
  /* Construct our kex1 packet so that we know whether we are supposed to
     send it as a guessed packet for our default method. */
  kex1_packet = ssh_tr_make_kex1(tr);
  
  /* Construct the outgoing KEXINIT packet. */
  packet = ssh_buffer_allocate();

  buffer_put_char(packet, SSH_MSG_KEXINIT);
  for (i = 0; i < 16; i++)
    buffer_put_char(packet, ssh_random_get_byte(tr->random_state));

  cp2 = ssh_kex_get_supported();
  cp = ssh_name_list_intersection(tr->params->kex_algorithms, cp2);
  ssh_xfree(cp2);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_public_key_get_supported();
  cp2 = ssh_public_key_list_canonialize(cp);
  ssh_xfree(cp);
  cp = ssh_name_list_intersection(cp2, host_key_algorithms);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_cipher(ciphers_c_to_s);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_cipher(ciphers_s_to_c);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_mac(macs_c_to_s);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_mac(macs_s_to_c);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_compression(compressions_c_to_s);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  cp = ssh_name_list_intersection_compression(compressions_s_to_c);
  buffer_put_uint32_string(packet, cp, strlen(cp));
  ssh_xfree(cp);

  /* Put language-strings to packet as empty strings.
     This is legal according to specs. */

  buffer_put_uint32_string(packet, "", 0);
  buffer_put_uint32_string(packet, "", 0);

  buffer_put_boolean(packet, kex1_packet != NULL);

  for (i = 0; i < 4; i++)
    buffer_put_char(packet, 0);

  /* Save the packet for key id calculation. */
  if (tr->server)
    {
      assert(tr->server_kexinit_packet == NULL);
      tr->server_kexinit_packet = packet;
    }
  else
    {
      assert(tr->client_kexinit_packet == NULL);
      tr->client_kexinit_packet = packet;
    }

  /* Send the packet to the outgoing stream. */
  ssh_tr_send_packet(tr, ssh_buffer_ptr(packet), ssh_buffer_len(packet));

  /* If we are to send a guessed KEX1 packet, send it now.  Note that the
     packet has already been saved for key negotiation. */
  if (kex1_packet != NULL)
    ssh_tr_send_packet(tr, ssh_buffer_ptr(kex1_packet),
                       ssh_buffer_len(kex1_packet));
}

/* Constructs and sends an outgoing KEXINIT packet with the algorithms in
   the params structure.  This does not update state. */

void ssh_tr_output_kexinit(SshTransportCommon tr)
{
  ssh_tr_output_kexinit_explicit(tr,
                                 tr->params->ciphers_c_to_s,
                                 tr->params->ciphers_s_to_c,
                                 tr->params->macs_c_to_s,
                                 tr->params->macs_s_to_c,
                                 tr->params->compressions_c_to_s,
                                 tr->params->compressions_s_to_c,
                                 tr->params->host_key_algorithms);
}

/* Initiate rekey after KEXINIT was received in interactive mode.  This will
   send our own kexinit packet in response.  The kexinit packet received
   as argument is saved for further processing. */

void ssh_tr_input_start_rekey(SshTransportCommon tr, SshBuffer *packet)
{
  SSH_DEBUG(5, ("ssh_tr_input_start_rekey"));

  /* We can get here in either of two states:
       1. We have requested to start rekey, and the other side is now
          replying.  (Note: it is possible that the requests cross; that case
          is indistinguishable from this case.)
       2. The other side is initiating rekey.
     The first case is identified by rekey already being true.
     Initialize for rekey unless we have already started it on our part. */
  if (!tr->rekey_request_sent)
    {
      /* Initialize state for rekey. */

      /* Cleanup the remains of any previous key exchange. */
      ssh_tr_kex_cleanup(tr);

      /* Mark that we are doing a rekey. */
      tr->doing_rekey = TRUE;

      assert(tr->sent_state == SENT_INTERACTIVE);
      assert(tr->received_state == RECEIVED_INTERACTIVE);
      tr->sent_state = SENT_VERSION;
  
      /* Send our own kexinit packet (possibly with guessed kex1).  This does
         not update state. */
      ssh_tr_output_kexinit(tr);

      /* Update send state. */
      tr->sent_state = SENT_KEXINIT;
    }
  
  /* Process the received kexinit packet identically to what we did during
     the initial key exchange.  This will update received_state. */
  ssh_tr_process_received_kexinit(tr, packet);
}

/* Try to receive and process a packet in interactive mode.  This returns
   FALSE if no packet is available or an error occurs, and TRUE if processing
   should continue.  If we return FALSE without trying to read, we will set
   the read_has_blocked flag to indicate that reads must be explicitly
   restarted. */

Boolean ssh_tr_input_interactive(SshTransportCommon tr)
{
  SshBuffer *packet;
  unsigned int packet_type;
  SshBuffer buffer;
  unsigned char seq_buf[4];

  SSH_DEBUG(5, ("ssh_tr_input_interactive"));
  
  /* If the queue of packets going up is too long, don't read any more packets
     until it has drained. */
  if (ssh_buffer_len(&tr->up_outgoing) >
      XMALLOC_MAX_SIZE - SSH_CONTROL_RESERVE - SSH_MAX_PAYLOAD_LENGTH ||
      ssh_buffer_len(&tr->up_outgoing) > SSH_BUFFERING_LIMIT)
    {
      SSH_DEBUG(5, ("ssh_tr_input_interactive: BLOCKING up_outgoing too big"));
      tr->read_has_blocked = TRUE;
      return FALSE;
    }
  
  /* Try to read a packet. */
  packet = ssh_tr_input_packet(tr);
  if (!packet)
    return FALSE;

  /* Get the packet type, without actually removing it from the packet. */
  packet_type = ssh_tr_peek_packet_type(packet);

  /* Process packets belonging to services by passing then up. */
  if (packet_type >= SSH_FIRST_SERVICE_PACKET)
    {
      /* Pass the packet upwards. */
      ssh_tr_up_send(tr, SSH_CROSS_PACKET,
                     ssh_buffer_ptr(packet), ssh_buffer_len(packet));
      ssh_buffer_free(packet);
      return TRUE;
    }

  /* Kex packets are illegal here, as are many of the known packets. */
  if (packet_type >= SSH_FIRST_KEX_PACKET ||
      packet_type == SSH_MSG_NEWKEYS ||
      packet_type == SSH_MSG_SERVICE_REQUEST ||
      packet_type == SSH_MSG_SERVICE_ACCEPT)
    {
      /* We should never receive kex packets in this state. */
      ssh_tr_up_disconnect(tr, TRUE, TRUE,
                           SSH_DISCONNECT_PROTOCOL_ERROR,
                           "Protocol error: packet %d in interactive",
                           packet_type);
      ssh_buffer_free(packet);
      return FALSE;
    }

  /* Currently, the only supported packet here is KEXINIT, which will
     initiate rekey. */
  if (packet_type == SSH_MSG_KEXINIT)
    {
      /* Start rekey.  This will cause the packet to be freed. */
      ssh_tr_input_start_rekey(tr, packet);
      return TRUE;
    }

  /* This is an unknown packet. */
  ssh_buffer_free(packet);
  ssh_buffer_init(&buffer);
  buffer_put_char(&buffer, SSH_MSG_UNIMPLEMENTED);
  SSH_PUT_32BIT(seq_buf, tr->incoming_sequence_number - 1);
  ssh_buffer_append(&buffer, seq_buf, 4);
  ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer),
                     ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
  return TRUE;
}

/* Process input from the connection. */

void ssh_tr_process_input(SshTransportCommon tr)
{
  Boolean ok = TRUE;

  SSH_DEBUG(5, ("ssh_tr_process_input"));
  
  while (ok)
    {
      ok = FALSE; 
      switch (tr->received_state)
        {
        case RECEIVED_NOTHING:
          ok = ssh_tr_input_version(tr);
          break;
          
        case RECEIVED_VERSION:
          ok = ssh_tr_input_kexinit(tr);
          break;

        case RECEIVED_KEXINIT:
          if ((tr->server ? tr->kex->server_input_kex1 
               : tr->kex->client_input_kex1) != NULL)
            ok = ssh_tr_input_kex1(tr);
          else
            ssh_tr_input_kex2(tr);
          break;
          
        case RECEIVED_KEX1_IGNORED:
          ok = ssh_tr_input_kex1(tr);
          break;
          
        case RECEIVED_KEX1_FINAL:
          ssh_tr_input_kex2(tr);
          break;
          
        case RECEIVED_KEX2:
          ok = ssh_tr_input_newkeys(tr);
          break;

        case RECEIVED_KEY_CHECK:
          /* We get moved to the next state after we receive the key check
             response. */
          SSH_DEBUG(5, ("ssh_tr_process_input: BLOCKED: wait key check"));
          ok = FALSE;
          break;
          
        case RECEIVED_NEWKEYS:
          /* If doing rekey, we can now proceed with receiving normal data. */
          if (tr->doing_rekey)
            {
              /* Send a SSH_CROSS_ALGORITHMS packet upwards. */
              ssh_tr_up_send_algorithms(tr);

              /* Update state. */
              tr->received_state = RECEIVED_INTERACTIVE;
              tr->rekey_request_sent = FALSE;
              ok = TRUE;
              break;
            }

          /* If server, wait for service request; if client, wait for service
             accept.  These will update state when appropriate. */
          if (tr->server)
            ok = ssh_tr_input_service_request(tr);
          else
            ok = ssh_tr_input_service_accept(tr);
          break;

        case RECEIVED_SERVICE_REQUEST:
          /* We are waiting for service accept or disconnect from up.
             We will be automatically advanced when we receive it. */
          SSH_DEBUG(5, ("ssh_tr_process_input: BLOCKING: up service accept wait"));
          tr->read_has_blocked = TRUE;
          ok = FALSE;
          break;
          
        case RECEIVED_INTERACTIVE:
          /* We are passing packets to the service. */
          ok = ssh_tr_input_interactive(tr);
          break;

        case RECEIVED_DEAD:
          /* We will not do anything more. */
          break;

        default:
          ssh_fatal("ssh_tr_process_input: unknown received state %d",
                (int)tr->received_state);
        }
    }
}

/* Sends a service request packet.  This does not update state. */

void ssh_tr_send_service_request(SshTransportCommon tr)
{
  SshBuffer buffer;

  SSH_DEBUG(5, ("ssh_tr_send_service_request"));
  
  ssh_buffer_init(&buffer);
  buffer_put_char(&buffer, SSH_MSG_SERVICE_REQUEST);
  buffer_put_uint32_string(&buffer, tr->service_name,
                            strlen(tr->service_name));
  ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer),
                     ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
}

/* Send pending output to the connection. */

void ssh_tr_process_output(SshTransportCommon tr)
{
  Boolean ok = TRUE;

  SSH_DEBUG(5, ("ssh_tr_process_output"));
  
  while (ok)
    {
      /* If we have pending data to output, process it first.  Note that
         this is processed also in SENT_DEAD state. */
      if (ssh_buffer_len(&tr->outgoing) > 0)
        {
          ok = ssh_tr_output_outgoing(tr);
          continue;
        }
      
      switch (tr->sent_state)
        {
        case SENT_NOTHING:
          /* This is technically against the draft. */
          /* Don't send anything before we receive the server's
             version string. */
          /* The reason for this kludge is that there existed a race
             condition. Sometimes ssh2-client executed the ssh1-client
             (=the version_callback got called), sometimes not,
             depending on whether it managed to process the server's
             version string before the server had closed the
             connection, and the stream got destroyed. It wasn't nice,
             so now we get to exec it in any case. Furthermore, this
             bug wasn't universal, and I found it when using my
             Linux-system.*/
          if (!tr->server && tr->version_compatibility &&
              tr->received_state < RECEIVED_VERSION )
            {
              /* We're in compatibility mode, we're client, and we
                 haven't received server's version string yet. */
              ok = FALSE;
              break;
            }
          
          /* Append version number to outgoing data. */
          ssh_buffer_append(&tr->outgoing, (unsigned char *) tr->own_version,
                        strlen(tr->own_version));
          
          /* No CR on compat mode */              
          if (strncmp("SSH-1.", tr->own_version, 6) != 0)
            ssh_buffer_append(&tr->outgoing, (unsigned char *) "\r", 1);
          ssh_buffer_append(&tr->outgoing, (unsigned char *) "\n", 1);
          tr->sent_state = SENT_VERSION;
          /* We loop again... */
          break;

        case SENT_VERSION:
          /* Do not send further data after version until we have received
             client version. */
          if (tr->server && tr->version_compatibility &&
              tr->received_state < RECEIVED_VERSION)
            {
              ok = FALSE;
              break;
            }

          tr->sent_state = SENT_KEXINIT;

          /* Construct and save a kexinit packet. */
          ssh_tr_output_kexinit(tr);
          /* We loop again... */
          break;
          
        case SENT_KEXINIT:
        case SENT_KEX1_FINAL:
          /* We must wait for received KEXINIT packet before we can
             continue.  Receiving KEXINIT will automatically trigger sending
             a new KEX1 packet if appropriate.  Thus, that need not be
             handled here.  Basically we just linger on here until it is time
             to send KEX2.  However, sending KEX2 is automatically triggered
             by receiving KEX1.  Thus, we need to wait until we have received
             KEX2.  But, NEWKEYS is automatically sent in response to receiving
             it, and thus we must wait here until NEWKEYS have been received.
             Simple, eh? */
          ok = FALSE;  /* We are automatically advanced when we have sent
                          NEWKEYS. */
          break;
          
        case SENT_NEWKEYS:
          /* If rekey, continue normal processing for output now that we have
             sent NEWKEYS. */
          if (tr->doing_rekey)
            {
              tr->sent_state = SENT_INTERACTIVE;
              tr->rekey_request_sent = FALSE;
              break; /* We loop again... */
            }

          /* If server, we are automatically advanced when we receive service
             request.  We just sleep here until then. */
          if (tr->server)
            {
              ok = FALSE;
              break;
            }

          /* We are the server, and this is the initial key exchange.
             Send service request. */
          ssh_tr_send_service_request(tr);
          tr->sent_state = SENT_SERVICE_REQUEST;
          break;  /* We loop again... */

        case SENT_SERVICE_REQUEST:
          /* (We only get here as client.)  If not using encryption, do
             not proceed until we have received service accept. */
          assert(!tr->server);
          if (strcmp(tr->c_to_s.cipher_name, "none") == 0 &&
              tr->received_state < RECEIVED_INTERACTIVE)
            {
              ok = FALSE;
              break;
            }
          /* We can proceed. */
          tr->sent_state = SENT_INTERACTIVE;
          /* Note: SSH_CROSS_STARTUP isn't sent until we receive service
             accept. */
          break; /* We loop again... */
          
        case SENT_INTERACTIVE:
          /* In this state, we don't really send anything automatically.
             Sending user data is handled in ssh_tr_up_write, and by
             ssh_tr_output_outgoing above. */
          ok = FALSE;
          break;
          
        case SENT_DEAD:
          /* We will not do anything more. */
          ok = FALSE;
          break;

        default:
          ssh_fatal("ssh_tr_process_output: unknown state %d",
                (int)tr->sent_state);
        }
    }
}

/* Called whenever input/output is available on the stream, or a special
   condition occurs. */

void ssh_tr_callback(SshStreamNotification notification,
                     void *context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(7, ("ssh_tr_callback %d", (int)notification));
  
  /* Just in case we would get queued events during destruction... */
  if (tr->connection == NULL)
    return;
  
  /* Process the notification. */
  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      ssh_tr_process_input(tr);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_tr_process_output(tr);
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_tr_up_disconnect(tr, TRUE, FALSE,
                           SSH_DISCONNECT_CONNECTION_LOST,
                           "The connection has been lost.");
      break;

    default:
      ssh_fatal("ssh_tr_callback: unknown notification %d",
            (int)notification);
    }
}

/* Process a cross-layer packet received from up_stream. */

void ssh_tr_process_up_incoming_packet(SshTransportCommon tr,
                                       unsigned int packet_type,
                                       const unsigned char *payload,
                                       size_t payload_len)
{
  SshBuffer buffer;
  Boolean always_display;
  unsigned int tr_packet_type;
  char *ciphers_c_to_s, *ciphers_s_to_c, *macs_c_to_s, *macs_s_to_c,
    *compressions_c_to_s, *compressions_s_to_c, *host_key_algorithms;
  unsigned char *msg, *msg_lang;
  SshUInt32 reason_code;

  SSH_DEBUG(5, ("ssh_tr_process_up_incoming_packet %d", packet_type));
  
  switch (packet_type)
    {
    case SSH_CROSS_PACKET:
      /* We have already done flow control; no need to do it here.  Just
         pass the packet down.  However, SSH_MSG_DISCONNECT packets get
         special handling; they cause SSH_CROSS_DISCONNECT to be
         relayed up. */
      tr_packet_type = payload[0];

      /* If waiting for service accept, don't accept anything else. */
      if (tr->received_state == RECEIVED_SERVICE_REQUEST &&
          tr_packet_type != SSH_MSG_DISCONNECT)
        ssh_fatal("ssh_tr_process_up_incoming_packet: expected "
                  "SERVICE_ACCEPT or DISCONNECT");

      if (tr_packet_type == SSH_MSG_DISCONNECT)
        ssh_fatal("ssh_tr_process_up_incoming_packet: "
                  "received SSH_MSG_DISCONNECT.  The interface has changed; "
                  "these now need to be sent as SSH_CROSS_DISCONNECT "
                  "cross-layer packets.");

      if (tr_packet_type < SSH_FIRST_SERVICE_PACKET &&
          tr_packet_type != SSH_MSG_DISCONNECT)
        {
          ssh_tr_up_disconnect(tr, TRUE, TRUE,
                               SSH_DISCONNECT_PROTOCOL_ERROR,
                               "Protocol error: service sending tr packet %d",
                               tr_packet_type);
          return;
        }
      
      /* Send the packet to the connection. */
      ssh_tr_send_packet(tr, payload, payload_len);
      break;

    case SSH_CROSS_DISCONNECT:
      /* Received a disconnect packet from up.  We should send it to the
         other side, relay it back up, and disconnect. */
      if (ssh_decode_array(payload, payload_len,
                           SSH_FORMAT_BOOLEAN, NULL,
                           SSH_FORMAT_UINT32, &reason_code,
                           SSH_FORMAT_UINT32_STR, &msg, NULL,
                           SSH_FORMAT_UINT32_STR, &msg_lang, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_tr_process_up_incoming_packet: bad DISCONNECT");

      SSH_DEBUG(5, ("received cross disconnect"));
      
      /* Send the DISCONNECT packet back up. */
      ssh_tr_up_send(tr, SSH_CROSS_DISCONNECT,
                     payload, payload_len);

      /* Send the disconnect packet to the connection. */
      ssh_buffer_init(&buffer);
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_CHAR, (unsigned int) SSH_MSG_DISCONNECT,
                        SSH_FORMAT_UINT32, reason_code,
                        SSH_FORMAT_UINT32_STR, msg,
                        strlen((char *) msg),
                        SSH_FORMAT_UINT32_STR, msg_lang,
                        strlen((char *) msg_lang),
                        SSH_FORMAT_END);
      ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      ssh_buffer_uninit(&buffer);

      /* Prepare for shutdown. */
      tr->up_outgoing_eof = TRUE;
      tr->received_state = RECEIVED_DEAD;
      tr->sent_state = SENT_DEAD;
      tr->outgoing_eof = TRUE;
      ssh_tr_output_outgoing(tr);
      ssh_tr_up_signal_input(tr);
      return;

    case SSH_CROSS_DEBUG:
      /* Received a debug packet from up.  We should send a debug
         packet to the other side. */
      if (ssh_decode_array(payload, payload_len,
                           SSH_FORMAT_BOOLEAN, &always_display,
                           SSH_FORMAT_UINT32_STR, &msg, NULL,
                           SSH_FORMAT_UINT32_STR, &msg_lang, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_tr_process_up_incoming_packet: bad DEBUG");

      /* Send the debug packet to the connection. */
      ssh_buffer_init(&buffer);
      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_CHAR, (unsigned int) SSH_MSG_DEBUG,
                        SSH_FORMAT_BOOLEAN, always_display,
                        SSH_FORMAT_UINT32_STR, msg,
                        strlen((char *) msg),
                        SSH_FORMAT_UINT32_STR, msg_lang,
                        strlen((char *) msg_lang),
                        SSH_FORMAT_END);
      ssh_tr_send_packet(tr, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      ssh_buffer_uninit(&buffer);
      break;
      
    case SSH_CROSS_REKEY_REQUEST:
      if (tr->received_state == RECEIVED_SERVICE_REQUEST)
        ssh_fatal("ssh_tr_process_up_incoming_packet: expected SERVICE_ACCEPT or DISCONNECT");
      
      /* Get new algorithms from the payload. */
      if (ssh_decode_array(payload, payload_len,
                           SSH_FORMAT_UINT32_STR, &ciphers_c_to_s, NULL,
                           SSH_FORMAT_UINT32_STR, &ciphers_s_to_c, NULL,
                           SSH_FORMAT_UINT32_STR, &macs_c_to_s, NULL,
                           SSH_FORMAT_UINT32_STR, &macs_s_to_c, NULL,
                           SSH_FORMAT_UINT32_STR, &compressions_c_to_s, NULL,
                           SSH_FORMAT_UINT32_STR, &compressions_s_to_c, NULL,
                           SSH_FORMAT_UINT32_STR, &host_key_algorithms, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("ssh_tr_process_up_incoming_packet: bad REKEY_REQUEST");

      /* Start rekey. */
      assert(tr->sent_state == SENT_INTERACTIVE);
      assert(tr->received_state == RECEIVED_INTERACTIVE);
      ssh_tr_kex_cleanup(tr);
      tr->doing_rekey = TRUE;
      tr->rekey_request_sent = TRUE;
      tr->sent_state = SENT_VERSION;
      ssh_tr_output_kexinit_explicit(tr, 
                                     ciphers_c_to_s,
                                     ciphers_s_to_c,
                                     macs_c_to_s, 
                                     macs_s_to_c,
                                     compressions_c_to_s, 
                                     compressions_s_to_c,
                                     host_key_algorithms);
      ssh_xfree(ciphers_c_to_s);
      ssh_xfree(ciphers_s_to_c);
      ssh_xfree(macs_c_to_s);
      ssh_xfree(macs_s_to_c);
      ssh_xfree(compressions_c_to_s);
      ssh_xfree(compressions_s_to_c);
      tr->sent_state = SENT_KEXINIT;
      break;

    case SSH_CROSS_SERVICE_ACCEPT:

      /* The service was accepted.  Send a service accept. */
      ssh_tr_send_simple_packet(tr, SSH_MSG_SERVICE_ACCEPT);
      
      /* Send a SSH_CROSS_STARTUP packet upwards. */
      ssh_tr_up_send_startup(tr);

      /* Send a SSH_CROSS_ALGORITHMS packet upwards. */
      ssh_tr_up_send_algorithms(tr);
  
      /* Update state. */
      tr->received_state = RECEIVED_INTERACTIVE;
      tr->sent_state = SENT_INTERACTIVE;

      ssh_tr_process_output(tr);
      ssh_tr_wake_up_input(tr);
      break;

    default:
      ssh_fatal("ssh_tr_process_up_incoming_packet: unexpected packet %d",
                packet_type);
    }
}

/* Up_stream read operation.  This is called by the generic streams code. */

int ssh_tr_up_read(void *context, unsigned char *buf, size_t size)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(7, ("ssh_tr_up_read"));
  
  /* We cannot read more data than is available in the buffer. */
  if (size > ssh_buffer_len(&tr->up_outgoing))
    size = ssh_buffer_len(&tr->up_outgoing);

  /* If no data available, return EOF or error. */
  if (size == 0)
    {
      if (tr->up_outgoing_eof)
        return 0;
      else
        {
          tr->up_read_blocked = TRUE;
          return -1;
        }
    }

  /* Copy data to user buffer. */
  memcpy(buf, ssh_buffer_ptr(&tr->up_outgoing), size);
  ssh_buffer_consume(&tr->up_outgoing, size);
  
  /* Make sure we are receiving more input from the network. */
  ssh_tr_wake_up_input(tr);
  
  return size;
}

/* Up_stream write operation.  This is called by the generic streams code
   WHEN STUFF IS COMING DOWN TO THE TRANSPORT LAYER */

int ssh_tr_up_write(void *context, const unsigned char *buf, size_t size)
{
  SshTransportCommon tr = context;
  size_t offset, payload_len, len;
  const unsigned char *ucp;

  SSH_DEBUG(5, ("ssh_tr_up_write"));

  if (tr->sent_state != SENT_INTERACTIVE &&
      tr->received_state != RECEIVED_SERVICE_REQUEST)
    {
      tr->up_write_blocked = TRUE;
      return -1;
    }

  if (tr->outgoing_eof)
    return 0;
  
  offset = 0;

  if (ssh_buffer_len(&tr->up_incoming) > 0)
    goto partial;
  
normal:

  while (ssh_buffer_len(&tr->outgoing) <
         XMALLOC_MAX_SIZE - SSH_MAX_TOTAL_PACKET_LENGTH - SSH_CONTROL_RESERVE
         && ssh_buffer_len(&tr->outgoing) < SSH_BUFFERING_LIMIT)
    {
      /* We only accept data from up in interactive state, and not after having
         already scheduled eof to connection. */
      if (tr->sent_state != SENT_INTERACTIVE &&
          tr->received_state != RECEIVED_SERVICE_REQUEST)
        break;

      if (tr->outgoing_eof)
        break;

      /* If we have processed all data, return now. */
      if (offset == size)
        return offset;

      /* If only partial packet available, do special processing. */
      if (size - offset < 4)
        goto partial; /* Need partial packet processing. */
      payload_len = SSH_GET_32BIT(buf + offset);
      if (size - offset < 4 + payload_len)
        goto partial; /* Need partial packet processing. */
      
      /* The entire packet is available; process it now. */
      ssh_tr_process_up_incoming_packet(tr, buf[offset + 4],
                                        buf + offset + 5, payload_len - 1);
      offset += 4 + payload_len;
    }
  /* We cannot process more data now. */
  if (offset > 0)
    return offset;
  tr->up_write_blocked = TRUE;
  return -1;

partial:
  /* Process partial packet. */
  len = ssh_buffer_len(&tr->up_incoming);
  if (len < 4)
    {
      len = 4 - len;
      if (size - offset < len)
        len = size - offset;
      ssh_buffer_append(&tr->up_incoming, buf + offset, len);
      offset += len;
    }
  if (ssh_buffer_len(&tr->up_incoming) < 4)
    return offset;
  ucp = ssh_buffer_ptr(&tr->up_incoming);
  payload_len = SSH_GET_32BIT(ucp);
  len = 4 + payload_len - ssh_buffer_len(&tr->up_incoming);
  if (len > size - offset)
    len = size - offset;
  ssh_buffer_append(&tr->up_incoming, buf + offset, len);
  offset += len;
  if (ssh_buffer_len(&tr->up_incoming) < 4 + payload_len)
    return offset;

  /* The entire packet is now in buffer. */
  ucp = ssh_buffer_ptr(&tr->up_incoming);
  ssh_tr_process_up_incoming_packet(tr, ucp[4], ucp + 5, payload_len - 1);

  /* Clear the incoming partial packet buffer and resume normal processing. */
  ssh_buffer_clear(&tr->up_incoming);
  goto normal;
}

/* Indicates that the application will not write anymore.  We will basically
   just close the connection. */

void ssh_tr_up_output_eof(void *context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(5, ("ssh_tr_up_output_eof"));

  if (tr->outgoing_eof)
    return;
  
  tr->outgoing_eof = TRUE;
  ssh_tr_output_outgoing(tr);
}

/* Sets the callback used to notify the application.  The callback may be
   NULL. */

void ssh_tr_up_set_callback(void *context,
                            SshStreamCallback up_callback,
                            void *up_context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(5, ("ssh_tr_up_set_callback"));
  
  /* Set the callback. */
  tr->up_callback = up_callback;
  tr->up_context = up_context;

  /* Cause the application callback to be called for both reading and
     writing (from the bottom of the event loop). */
  ssh_tr_up_signal_input(tr);
  ssh_tr_up_signal_output(tr);
}

/* Destroys the stream context. */

void ssh_tr_up_destroy(void *context)
{
  SshTransportCommon tr = context;

  SSH_DEBUG(5, ("ssh_tr_up_destroy"));
  
  tr->up_stream = NULL;
  tr->up_callback = NULL;
  tr->received_state = RECEIVED_DEAD;
  tr->sent_state = SENT_DEAD;

  if (ssh_buffer_len(&tr->outgoing) == 0 ||
      tr->connection == NULL)
    ssh_tr_destroy_now(tr);
}

/* Method table for the up_stream. */

const SshStreamMethodsTable ssh_tr_methods =
{
  ssh_tr_up_read,
  ssh_tr_up_write,
  ssh_tr_up_output_eof,
  ssh_tr_up_set_callback,
  ssh_tr_up_destroy
};

/* Creates the SshTransportCommon object, and performs initializations that
   are common to client and server.  Either client or server initialization
   should be performed after this call. */

SshTransportCommon ssh_tr_create(SshStream connection,
                                 Boolean server,
                                 Boolean compatibility,
                                 Boolean fake_old_version,
                                 const char *application_version,
                                 SshRandomState random_state,
                                 SshTransportParams params)
{
  SshTransportCommon tr;
  char buf[256];

  tr = ssh_xcalloc(sizeof(*tr), 1);

  /* Initialize general state. */
  tr->server = server;
  tr->version_compatibility = compatibility;
  tr->doing_rekey = FALSE;
  tr->rekey_request_sent = FALSE;
  tr->read_has_blocked = FALSE;
  tr->sent_state = SENT_NOTHING;
  tr->received_state = RECEIVED_NOTHING;
  tr->connection = connection;
  tr->random_state = random_state;
  tr->params = params;

  /* Initialize packet sequence numbers. */
  tr->incoming_sequence_number = 0;
  tr->outgoing_sequence_number = 0;

  tr->outgoing_eof = FALSE;
  
  /* Initialize incoming/outgoing buffers. */
  ssh_buffer_init(&tr->outgoing);
  tr->incoming_packet = NULL;
  ssh_buffer_init(&tr->up_outgoing);
  ssh_buffer_init(&tr->up_incoming);
  tr->up_write_blocked = FALSE;
  tr->up_read_blocked = FALSE;

  /* Initialize guessed algorithms. */
  tr->guessed_kex = ssh_name_list_get_name(params->kex_algorithms);

  /* We really should make a better guess here..
   * the client side should send the host key previously stored. (XXX) */

  tr->guessed_host_key = ssh_name_list_get_name(params->host_key_algorithms);
  tr->kex = ssh_kex_lookup(tr->guessed_kex);
  if (!tr->kex)
    ssh_fatal("ssh_tr_create: guessed kex '%.100s' not found",
          tr->guessed_kex);

  /* Initialize current algorithms. */
  tr->kex_name = ssh_xstrdup(tr->guessed_kex);
  tr->host_key_name = ssh_xstrdup(tr->guessed_host_key);
  tr->host_key_names = ssh_xstrdup(params->host_key_algorithms);
  tr->c_to_s.cipher_name = ssh_xstrdup("none");
  tr->c_to_s.mac_name = ssh_xstrdup("none");
  tr->c_to_s.compression_name = ssh_xstrdup("none");
  tr->s_to_c.cipher_name = ssh_xstrdup("none");
  tr->s_to_c.mac_name = ssh_xstrdup("none");
  tr->s_to_c.compression_name = ssh_xstrdup("none");
  if (tr->server)
    {
      ssh_tr_set_keys(tr, &tr->c_to_s, &tr->incoming_granularity, FALSE,
                      &tr->incoming_cipher, &tr->incoming_mac,
                      &tr->compression_incoming);
      ssh_tr_set_keys(tr, &tr->s_to_c, &tr->outgoing_granularity, TRUE,
                      &tr->outgoing_cipher, &tr->outgoing_mac,
                      &tr->compression_outgoing);
    }
  else
    {
      ssh_tr_set_keys(tr, &tr->s_to_c, &tr->incoming_granularity, FALSE,
                      &tr->incoming_cipher, &tr->incoming_mac,
                      &tr->compression_incoming);
      ssh_tr_set_keys(tr, &tr->c_to_s, &tr->outgoing_granularity, TRUE,
                      &tr->outgoing_cipher, &tr->outgoing_mac,
                      &tr->compression_outgoing);
    }

  tr->compression_buffer = ssh_buffer_allocate();
  tr->compressed_incoming_bytes = 0;
  tr->uncompressed_incoming_bytes = 0;
  tr->compressed_outgoing_bytes = 0;
  tr->uncompressed_outgoing_bytes = 0;
  
  assert(sizeof(buf) >= 256);
  snprintf(buf, 256 - 3,
           fake_old_version ? SSH_VERSION_STRING_COMPAT : SSH_VERSION_STRING,
           application_version);
  tr->own_version = ssh_xstrdup(buf);

  tr->public_host_key = NULL;
  tr->public_server_key = NULL;
  tr->public_host_key_blob = NULL;
  tr->public_server_key_blob = NULL;
  tr->private_host_key = NULL;
  tr->private_server_key = NULL;
  
  tr->session_identifier_len = 0;
  tr->exchange_hash_len = 0;

  tr->ssh_old_mac_bug_compat = FALSE;
  tr->ssh_old_keygen_bug_compat = FALSE;
  tr->ssh_old_publickey_bug_compat = FALSE;
  
  /* initialize the key excange parameters */

  ssh_mp_init(tr->dh_p);
  ssh_mp_init(tr->dh_g);
  ssh_mp_init(tr->dh_e);
  ssh_mp_init(tr->dh_f);
  ssh_mp_init(tr->dh_k);
  ssh_mp_init(tr->dh_secret);

  return tr;
}

/* Finalizes the creation of the transport layer protocol.  Wraps it into
   a stream, and returns the stream.  The lower-level object should not
   be accessed after this call; the object will be automatically destroyed
   when the stream is destroyed. */

SshStream ssh_tr_create_final(SshTransportCommon tr)
{
  SshStream up_stream;
  up_stream = ssh_stream_create(&ssh_tr_methods, (void *)tr);
  tr->up_stream = up_stream;
  ssh_stream_set_callback(tr->connection, ssh_tr_callback, (void *)tr);
  return up_stream;
}

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
                                    const char *soft_version)
{
  size_t vlen;

  assert(version != NULL);
  assert(soft_version != NULL);
  vlen = strlen(version);
  return ((strncmp(soft_version, version, vlen) == 0) && 
          (!(isdigit(soft_version[vlen]))));
}

/* XXX eliminate calls to assert or ssh_fatal on data that might come from
   the line (i.e., call disconnect instead of aborting on errors). */

