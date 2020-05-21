/*

t-tr.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Test program for the SSH2 transport layer protocol.
                   
*/

/*
 * $Id: t-tr.c,v 1.21 1999/05/04 02:20:00 kivinen Exp $
 * $Log: t-tr.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtrans.h" 
#include "sshmsgs.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "sshbufaux.h"
#include "sshgetput.h"
#include "pubkeyencode.h"
#include "sshcipherlist.h"
#include "sshunixeloop.h"

#define PASSES 5

#undef DEBUG
#undef DUMP_PACKETS

#define SERVER_NAME "localhost"
#define SSH_VERSION "t-tr"

SshRandomState random_state;
SshBuffer testdata;
SshTcpListener listener;

typedef enum {
  OP_EXPECT_SERVICE_REQUEST=0,/* ARG: name */
  OP_EXPECT_DISCONNECT,       /* ARG: string */
  OP_EXPECT_EOF,
  OP_EXPECT_STARTUP,
  OP_EXPECT_ALGORITHMS,
  OP_EXPECT_PACKET,           /* ARG: packet type */
  OP_EXPECT_TEST_STREAM,      /* ARG: packet type */
  OP_SEND_SERVICE_ACCEPT,
  OP_SEND_REKEY_REQUEST,
  OP_SEND_PACKET,             /* ARG: packet type */
  OP_SEND_TEST_STREAM,        /* ARG: packet type */
  OP_SEND_DISCONNECT,         /* ARG: string */
  OP_SEND_EOF,
  OP_END
} TestOp;

const char *opnames[] =
{
  "OP_EXPECT_SERVICE_REQUEST",
  "OP_EXPECT_DISCONNECT",
  "OP_EXPECT_EOF",
  "OP_EXPECT_STARTUP",
  "OP_EXPECT_ALGORITHMS",
  "OP_EXPECT_PACKET",
  "OP_EXPECT_TEST_STREAM",
  "OP_SEND_SERVICE_ACCEPT",
  "OP_SEND_REKEY_REQUEST",
  "OP_SEND_PACKET",
  "OP_SEND_TEST_STREAM",
  "OP_SEND_DISCONNECT",
  "OP_SEND_EOF",
  "OP_END"
};

typedef struct {
  TestOp op;
  char *arg;
} TestScript;

#define MAX_SCRIPT_LEN 100

typedef struct {
  char *name;
  char *service;
  char *c_to_s_algs;
  char *s_to_c_algs;
  TestScript client_script[MAX_SCRIPT_LEN];
  TestScript server_script[MAX_SCRIPT_LEN];
} TestCase;

TestCase tests[] =
{

  /* -- basic -- */

  { "basic", "TEST", NULL, NULL,
    { { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_PACKET, "250" },
      { OP_SEND_PACKET, "251" },
      { OP_SEND_PACKET, "252" },
      { OP_SEND_TEST_STREAM, "253" },
      { OP_SEND_DISCONNECT, "TEST DISCONNECT BASIC" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT BASIC" },
      { OP_EXPECT_EOF },
      { OP_END }
    },
    { { OP_EXPECT_SERVICE_REQUEST, "TEST" },
      { OP_SEND_SERVICE_ACCEPT },
      { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_PACKET, "250" },
      { OP_EXPECT_PACKET, "251" },
      { OP_EXPECT_PACKET, "252" },
      { OP_EXPECT_TEST_STREAM, "253" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT BASIC" },
      { OP_EXPECT_EOF },
      { OP_END }
    }},

  /* -- compression -- */

  { "compression", "TEST",
    "3des-cbc:3des-cbc:hmac-sha1:hmac-sha1:zlib:zlib",
    "3des-cbc:3des-cbc:hmac-sha1:hmac-sha1:zlib:zlib",
    { { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_PACKET, "100" },
      { OP_SEND_PACKET, "101" },
      { OP_SEND_PACKET, "102" },
      { OP_SEND_TEST_STREAM, "103" },
      { OP_SEND_DISCONNECT, "TEST DISCONNECT COMPRESSION" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT COMPRESSION" },
      { OP_EXPECT_EOF },
      { OP_END }
    },
    { { OP_EXPECT_SERVICE_REQUEST, "TEST" },
      { OP_SEND_SERVICE_ACCEPT },
      { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_PACKET, "100" },
      { OP_EXPECT_PACKET, "101" },
      { OP_EXPECT_PACKET, "102" },
      { OP_EXPECT_TEST_STREAM, "103" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT COMPRESSION" },
      { OP_EXPECT_EOF },
      { OP_END }
    }},

  /* -- wrong guess -- */

  { "wrong guess", "TEST",
    "blowfish-cbc,3des-cbc,idea-cbc:blowfish-cbc,3des-cbc,idea-cbc:"
    "hmac-sha,hmac-md5,hmac-sha1-96,hmac-md5-96,hmac-sha:"
    "hmac-sha,hmac-md5,hmac-sha1-96,md5-96,hmac-sha1:"
    "none:zlib",
    "none,idea-cbc,blowfish-cbc,3des-cbc,idea-cbc:"
    "none,idea-cbc,blowfish-cbc,3des-cbc,idea-cbc:"
    "hmac-md5,hmac-sha1,hmac-sha1-96,kissa:"
    "hmac-md5,hmac-sha1,hmac-sha1-96,koira:"
    "none:zlib",
    { { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_PACKET, "100" },
      { OP_SEND_PACKET, "101" },
      { OP_SEND_PACKET, "102" },
      { OP_SEND_TEST_STREAM, "103" },
      { OP_SEND_DISCONNECT, "TEST DISCONNECT WRONG GUESS" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT WRONG GUESS" },
      { OP_EXPECT_EOF },
      { OP_END }
    },
    { { OP_EXPECT_SERVICE_REQUEST, "TEST" },
      { OP_SEND_SERVICE_ACCEPT },
      { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_PACKET, "100" },
      { OP_EXPECT_PACKET, "101" },
      { OP_EXPECT_PACKET, "102" },
      { OP_EXPECT_TEST_STREAM, "103" },
      { OP_EXPECT_DISCONNECT, "TEST DISCONNECT WRONG GUESS" },
      { OP_EXPECT_EOF },
      { OP_END }
    }},
  { "bad service request", "BADSERVICE", NULL, NULL,
    { { OP_EXPECT_DISCONNECT, "BAD SERVICE DISCONNECT" },
      { OP_EXPECT_EOF },
      { OP_END }
    },
    { { OP_EXPECT_SERVICE_REQUEST, "BADSERVICE" },
      { OP_SEND_DISCONNECT, "BAD SERVICE DISCONNECT" },
      { OP_EXPECT_DISCONNECT, "BAD SERVICE DISCONNECT" },
      { OP_EXPECT_EOF },
      { OP_END }
    }},

  /* -- rekey -- */

  { "rekey", "REKEYTEST", NULL, NULL,
    { { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_TEST_STREAM, "100" },
      { OP_EXPECT_TEST_STREAM, "101" },
      { OP_SEND_REKEY_REQUEST, 
        "3des-cbc,none:3des-cbc,none:"
        "hmac-md5,hmac-sha1:hmac-sha1-96:"
        "zlib:zlib" },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_TEST_STREAM, "102" },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_TEST_STREAM, "103" },
      { OP_SEND_EOF },
      { OP_EXPECT_EOF },
      { OP_END }
    },
    { { OP_EXPECT_SERVICE_REQUEST, "REKEYTEST" },
      { OP_SEND_SERVICE_ACCEPT },
      { OP_EXPECT_STARTUP },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_TEST_STREAM, "100" },
      { OP_SEND_TEST_STREAM, "101" },
      { OP_EXPECT_ALGORITHMS },
      { OP_EXPECT_TEST_STREAM, "102" },
      { OP_SEND_REKEY_REQUEST, 
        "none:none:"
        "hmac-sha1-96:hmac-sha1-96:"
        "none:none" },
      { OP_EXPECT_ALGORITHMS },
      { OP_SEND_TEST_STREAM, "103" },
      { OP_SEND_EOF },
      { OP_EXPECT_EOF },
      { OP_END }
    }},
  { NULL }
};

typedef struct {
  SshStream stream;
  TestScript *script;
  const char *side;
  const char *name;
  Boolean input_blocked;
  Boolean output_blocked;

  SshBuffer *incoming;
  unsigned int incoming_offset;
  unsigned int incoming_len;
  SshBuffer outgoing;
  Boolean outgoing_eof;

  unsigned int stream_offset;
} *Handler;

Handler client_handler, server_handler; /* For easy debugging access only */
unsigned int end_of_script_count = 0;

void handler_callback(SshStreamNotification notification, void *context);

/* Read a cross-layer packet from the transport layer protocol.  Returns the
   packet, or NULL if no packet is yet available.  The caller is responsible
   for freeing the packet. */

SshBuffer *handler_input_cross(Handler c)
{
  int len;
  unsigned char *cp;
  SshBuffer *packet;
  
  packet = c->incoming;
  if (packet == NULL)
    {
      /* No partial packet already received; initialize for receiving packet
         header. */
      packet = ssh_buffer_allocate();
      c->incoming = packet;
      c->incoming_offset = 0;
      c->incoming_len = 4;
      ssh_buffer_append_space(packet, &cp, c->incoming_len);
    }

keep_reading:
  /* Keep reading until either entire header or entire packet received
     (determined by incoming_len).  Space has already been allocated
     in the buffer. */
  while (c->incoming_offset < c->incoming_len)
    {
      len = c->incoming_len - c->incoming_offset;
      cp = ssh_buffer_ptr(packet);
      cp += c->incoming_offset;
      len = ssh_stream_read(c->stream, cp, len);
      if (len < 0)
        return NULL;
      if (len == 0)
        ssh_fatal("%s: handler_input_cross: received unexpected eof", c->side);
      c->incoming_offset += len;
    }

  /* If this was the header received, read the rest of the packet if there
     is non-zero length payload. */
  if (c->incoming_len == 4 && c->incoming_offset == 4)
    {
      cp = ssh_buffer_ptr(packet);
      c->incoming_len = 4 + SSH_GET_32BIT(cp);
      if (c->incoming_len > 4)
        {
          ssh_buffer_append_space(packet, &cp, c->incoming_len - 4);
          goto keep_reading;
        }
    }

  /* The entire packet has been received.  Return it. */
  c->incoming = NULL;
  cp = ssh_buffer_ptr(packet);

  return packet;
}

/* Read a cross-layer packet, expecting a packet of the given type.
   Generates a fatal error if a non-matching packet is received.  Returns
   the payload, or NULL if no packet is yet available. */

SshBuffer *handler_input_expect_cross(Handler c, unsigned int expect_type)
{
  SshBuffer *packet;
  const unsigned char *cp;
  unsigned int packet_type;

  packet = handler_input_cross(c);
  if (!packet)
    return NULL;

  cp = ssh_buffer_ptr(packet);
  packet_type = (unsigned int) cp[4];
  if (packet_type != expect_type)
    ssh_fatal("%s: handler_input_expect_cross: got %d expected %d",
          c->side, packet_type, expect_type);
  /* Remove cross-layer header and return the payload. */
  ssh_buffer_consume(packet, 5);
  return packet;
}

/* Reads a normal packet (inside a SSH_CROSS_PACKET packet).  Generates
   a fatal error if a non-matching packet is received.  Returns the packet
   (without packet type) or NULL if no packet is yet available. */

SshBuffer *handler_input_expect_packet(Handler c, unsigned int expect_type)
{
  SshBuffer *packet;
  const unsigned char *cp;
  unsigned int packet_type;

  packet = handler_input_expect_cross(c, SSH_CROSS_PACKET);
  if (!packet)
    return NULL;

  cp = ssh_buffer_ptr(packet);
  packet_type = buffer_get_char(packet);
  if (packet_type != expect_type)
    ssh_fatal("%s: handler_input_expect_packet: got %d expected %d",
              c->side, packet_type, expect_type);
  return packet;
}
  
/* Processes input from the transport layer protocol.  This is called whenever
   data is available from the transport layer object.  This returns
   TRUE if output should be awakened. */

Boolean handler_input(Handler c)
{
  SshBuffer *packet;
  char *cp, *cp2;
  int len;
  unsigned char byte;
  Boolean wake_up_output = FALSE;

  for (;; c->script++)
    {
#ifdef DEBUG
      ssh_debug("%s: handler_input: %s", c->side, opnames[c->script->op]);
#endif
      switch (c->script->op)
        {
        case OP_EXPECT_SERVICE_REQUEST:
          packet = handler_input_expect_cross(c,
                                              SSH_CROSS_SERVICE_REQUEST);
          if (!packet)
            return FALSE;
          cp = buffer_get_uint32_string(packet, NULL);
          if (strcmp(cp, c->script->arg) != 0)
            ssh_fatal("%s: handler_input: service request mismatch: %s vs %s",
                  c->side, c->script->arg, cp);
          ssh_xfree(cp);
          ssh_buffer_free(packet);
          break;

        case OP_EXPECT_DISCONNECT:
          packet = handler_input_expect_cross(c, SSH_CROSS_DISCONNECT);
          if (!packet)
            return FALSE;
          (void)buffer_get_boolean(packet);
          (void)buffer_get_int(packet);
          cp = buffer_get_uint32_string(packet, NULL);
          ssh_xfree(buffer_get_uint32_string(packet, NULL)); /* lang. tag */
          if (strcmp(cp, c->script->arg) != 0)
            ssh_fatal("%s: handler_input: disconnect mismatch: %s vs %s",
                  c->side, c->script->arg, cp);
          ssh_xfree(cp);
          ssh_buffer_free(packet);
          break;
          
        case OP_EXPECT_EOF:
          len = ssh_stream_read(c->stream, &byte, 1);
          if (len < 0)
            return FALSE;
          if (len != 0)
            ssh_fatal("%s: handler_input: EOF expected, received 0x%0x",
                  c->side, byte);
          break;
          
        case OP_EXPECT_STARTUP:
          packet = handler_input_expect_cross(c, SSH_CROSS_STARTUP);
          if (!packet)
            return FALSE;
          ssh_buffer_free(packet);
          break;
          
        case OP_EXPECT_ALGORITHMS:
          packet = handler_input_expect_cross(c, SSH_CROSS_ALGORITHMS);
          if (!packet)
            return FALSE;
          ssh_buffer_free(packet);
          break;

        case OP_EXPECT_PACKET:
          packet = handler_input_expect_packet(c, atoi(c->script->arg));
          if (!packet)
            return FALSE;
          ssh_buffer_free(packet);
          break;
          
        case OP_EXPECT_TEST_STREAM:
          while (c->stream_offset < ssh_buffer_len(&testdata))
            {
              packet = handler_input_expect_packet(c, atoi(c->script->arg));
              if (!packet)
                return FALSE;
              cp = ssh_buffer_ptr(packet);
              cp2 = ssh_buffer_ptr(&testdata);
              if (memcmp(cp, cp2 + c->stream_offset, ssh_buffer_len(packet)) != 0)
                ssh_fatal("%s: handler_input: TEST_STREAM compare fail offset %d",
                      c->side, c->stream_offset);
              c->stream_offset += ssh_buffer_len(packet);
              ssh_buffer_free(packet);
            }
          c->stream_offset = 0;
          break;
          
        case OP_SEND_SERVICE_ACCEPT:
        case OP_SEND_REKEY_REQUEST:
        case OP_SEND_PACKET:
        case OP_SEND_TEST_STREAM:
        case OP_SEND_DISCONNECT:
        case OP_SEND_EOF:
          wake_up_output = TRUE;
          goto out;

        case OP_END:
          return FALSE;

        default:
          ssh_fatal("%s: handler_input: unknown op %d",
                c->side, (int)c->script->op);
        }
    }
out:
  c->input_blocked = TRUE;
  return wake_up_output;
}

/* Writes as much buffered outgoing data as possible to the transport
   layer protocol.  The buffered data is assumed to consist of cross layer
   packets.  Returns TRUE if all buffered data was written. */

Boolean handler_output_outgoing(Handler c)
{
  int len;
#ifdef DEBUG
  ssh_debug("handler_output_outgoing");
#endif
#ifdef DUMP_PACKETS
  buffer_dump(&c->outgoing); 
#endif
 

  while (ssh_buffer_len(&c->outgoing) > 0)
    {
      len = ssh_buffer_len(&c->outgoing);
      len = ssh_stream_write(c->stream, ssh_buffer_ptr(&c->outgoing), len);
      if (len == 0)
        ssh_fatal("%s: handler_output: error writing to stream", c->side);
      if (len < 0)
        return FALSE;
      ssh_buffer_consume(&c->outgoing, len);
    }

  if (c->outgoing_eof)
    ssh_stream_output_eof(c->stream);

  return TRUE;
}

/* Sends a cross-layer packet down to the transport layer protocol. */

void handler_send_cross(Handler c, unsigned int cross_type,
                        const unsigned char *payload, size_t len)
{
  unsigned char header[5];

  SSH_PUT_32BIT(header, len + 1);
  header[4] = cross_type;
  ssh_buffer_append(&c->outgoing, header, 5);
  ssh_buffer_append(&c->outgoing, payload, len);
}
/* Stores each of the colon-delimited parts into the buffer. */

void store_delimited_strings(SshBuffer *packet, const char *arg)
{
  char *copy, *part;

  copy = ssh_xstrdup(arg);
  for (part = strtok(copy, ":"); part; part = strtok(NULL, ":"))
    buffer_put_uint32_string(packet, part, strlen(part));
  ssh_xfree(copy);
}
      

/* Called whenever data can be output to the transport layer protocol.
   This returns TRUE if input should be awakened. */

Boolean handler_output(Handler c)
{
  SshBuffer buffer;
  unsigned int len;
  const unsigned char *cp;
  Boolean wake_up_input = FALSE;
  
  for (;; c->script++)
    {
#ifdef DEBUG
      ssh_debug("%s: handler_output: %s", c->side, opnames[c->script->op]);
#endif
      switch (c->script->op)
        {
        case OP_EXPECT_SERVICE_REQUEST:
        case OP_EXPECT_DISCONNECT:
        case OP_EXPECT_EOF:
        case OP_EXPECT_STARTUP:
        case OP_EXPECT_ALGORITHMS:
        case OP_EXPECT_PACKET:
        case OP_EXPECT_TEST_STREAM:
          wake_up_input = TRUE;
          goto out;
          
        case OP_SEND_SERVICE_ACCEPT:
          handler_send_cross(c, SSH_CROSS_SERVICE_ACCEPT, NULL, 0);
          break;
          
        case OP_SEND_REKEY_REQUEST:
          ssh_buffer_init(&buffer);
          store_delimited_strings(&buffer, c->script->arg);
          handler_send_cross(c, SSH_CROSS_REKEY_REQUEST,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
          ssh_buffer_uninit(&buffer);
          break;
          
        case OP_SEND_PACKET:
          ssh_buffer_init(&buffer);
          buffer_put_char(&buffer, atoi(c->script->arg));
          handler_send_cross(c, SSH_CROSS_PACKET,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
          ssh_buffer_uninit(&buffer);
          break;

        case OP_SEND_TEST_STREAM:
          while (c->stream_offset < ssh_buffer_len(&testdata))
            {
              if (ssh_buffer_len(&c->outgoing) >
                  XMALLOC_MAX_SIZE - SSH_MAX_PAYLOAD_LENGTH - 5000 ||
                  ssh_buffer_len(&c->outgoing) > 50000 - SSH_MAX_PAYLOAD_LENGTH)
                if (!handler_output_outgoing(c))
                  goto out;
              len = random() % (SSH_MAX_PAYLOAD_LENGTH - 3);
              if (len > ssh_buffer_len(&testdata) - c->stream_offset)
                len = ssh_buffer_len(&testdata) - c->stream_offset;
              ssh_buffer_init(&buffer);
              buffer_put_char(&buffer, atoi(c->script->arg));
              cp = ssh_buffer_ptr(&testdata);
              ssh_buffer_append(&buffer, cp + c->stream_offset, len);
              c->stream_offset += len;
              handler_send_cross(c, SSH_CROSS_PACKET,
                                 ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
              ssh_buffer_uninit(&buffer);
            }
          c->stream_offset = 0;
          break;

        case OP_SEND_DISCONNECT:
          ssh_buffer_init(&buffer);
          buffer_put_boolean(&buffer, TRUE);
          buffer_put_int(&buffer, SSH_DISCONNECT_BY_APPLICATION);
          buffer_put_uint32_string(&buffer, c->script->arg,
                                    strlen(c->script->arg));
          buffer_put_uint32_string(&buffer, "", 0);
          handler_send_cross(c, SSH_CROSS_DISCONNECT,
                             ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
          ssh_buffer_uninit(&buffer);
          break;

        case OP_SEND_EOF:
          c->outgoing_eof = TRUE;
          break;
          
        case OP_END:
          goto out;

        default:
          ssh_fatal("%s: handler_output: unknown op %d",
                c->side, (int)c->script->op);
        }
    }

out:
  c->output_blocked = handler_output_outgoing(c);
  return wake_up_input;
}

/* Called whenever the transport layer protocol wants to notify us. */

void handler_callback(SshStreamNotification notification, void *context)
{
  Handler c = context;
  SshTransportStatistics stats;
  Boolean cont = FALSE;
  
#ifdef DEBUG
  ssh_debug("\n** %s: handler_callback %s **\n", c->side,
            opnames[c->script->op]);
#endif

  do
    {
      switch (notification)
        {
        case SSH_STREAM_INPUT_AVAILABLE:
          cont = handler_input(c);
          if (cont)
            notification = SSH_STREAM_CAN_OUTPUT;
          break;
        case SSH_STREAM_CAN_OUTPUT:
          cont = handler_output(c);
          if (cont)
            notification = SSH_STREAM_INPUT_AVAILABLE;
          break;
        case SSH_STREAM_DISCONNECTED:
          ssh_fatal("%s: handler_callback: DISCONNECT", c->side);
          
        default:
          ssh_fatal("%s: handler_callback: unexpected %d",
                    c->side, (int)notification);
        }

      if (c->script->op == OP_END)
        {
          /* End of script reached.  Destroy handler. */
#ifdef DEBUG
          ssh_debug("%s: End of script reached", c->side);
#endif
          cont = FALSE;
          ssh_transport_get_statistics(c->stream, &stats);
#ifdef DEBUG

          ssh_debug("%s: %lu/%lu bytes in, %lu/%lu out, %lu packets in, "
                    "%lu out\n",
                    c->side,
                    stats.compressed_incoming_bytes,
                    stats.uncompressed_incoming_bytes,
                    stats.compressed_outgoing_bytes,
                    stats.uncompressed_outgoing_bytes,
                    stats.incoming_packets, stats.outgoing_packets);
#endif

          ssh_stream_destroy(c->stream);
          memset(c, 'F', sizeof(*c));
          ssh_xfree(c);
          end_of_script_count++;
        }
    }
  while (cont);
}

void create_server_keys(SshPrivateKey *host, SshPrivateKey *server,
                        unsigned char **blob, unsigned int *len)
{
  SshPublicKey public_host_key;

#ifdef DEBUG
  ssh_debug("generating host key");
#endif
  if (ssh_private_key_generate(random_state, host, 
                               SSH_CRYPTO_DSS,
                               SSH_PKF_SIZE, 768, SSH_PKF_END)
      != SSH_CRYPTO_OK)
    ssh_fatal("Generating host key failed");
#ifdef DEBUG
  ssh_debug("generating server key");
#endif

  if (ssh_private_key_generate(random_state, server,
                               SSH_CRYPTO_DSS,
                               SSH_PKF_SIZE, 512, SSH_PKF_END)
      != SSH_CRYPTO_OK)
    ssh_fatal("Generating server key failed");

#ifdef DEBUG
  ssh_debug("deriving public host key blob");
#endif

  public_host_key = ssh_private_key_derive_public_key(*host);
  *len = ssh_encode_pubkeyblob(public_host_key, blob);

  if (*len == 0)
    ssh_fatal("deriving public key failed.");

#ifdef DEBUG
  ssh_debug("ok");
#endif

  ssh_public_key_free(public_host_key);
#ifdef DEBUG
  ssh_debug("create_server_keys done.");
#endif
}

void update_algs(SshTransportParams params, const char *algs)
{
  char *copy;
  char *cp, **dest;
  int i;

  if (algs == NULL)
    return;
  
  copy = ssh_xstrdup(algs);
  for (i = 0, cp = strtok(copy, ":"); cp; i++, cp = strtok(NULL, ":"))
    {
      switch (i)
        {
        case 0: /* c_to_s_cipher */
          dest = &params->ciphers_c_to_s;
          break;
        case 1: /* s_to_c_cipher */
          dest = &params->ciphers_s_to_c;
          break;
        case 2: /* c_to_s_mac */
          dest = &params->macs_c_to_s;
          break;
        case 3: /* s_to_c_mac */
          dest = &params->macs_s_to_c;
          break;
        case 4: /* c_to_s_compression */
          dest = &params->compressions_c_to_s;
          break;
        case 5: /* s_to_c_compression */
          dest = &params->compressions_s_to_c;
          break;
        default:
          dest = NULL; /* to avoid compiler warning... */
          ssh_fatal("too many algorithms: %s", cp);
        }
#ifdef DEBUG
      ssh_debug("alg: %s\n", cp);
#endif
      if (*dest)
        ssh_xfree(*dest);
      *dest = ssh_xstrdup(cp);
    }
  ssh_xfree(copy);
}

void listener_callback(SshIpError status, SshStream stream, void *context)
{
  SshPrivateKey private_host_key, private_server_key;
  unsigned char *blob;
  unsigned int blob_len = 0;
  Handler c;
  TestCase *testcase = context;
  SshTransportParams params;
  
  if (status != SSH_IP_NEW_CONNECTION)
    ssh_fatal("listener_callback: status %d", status);

#ifdef DEBUG
  ssh_debug("listener: new connection");
#endif
  
  create_server_keys(&private_host_key, &private_server_key, &blob, &blob_len);
  
  params = ssh_transport_create_params();
  update_algs(params, testcase->s_to_c_algs);

  c = ssh_xcalloc(sizeof(*c), 1);

  c->stream = ssh_transport_server_wrap(stream, random_state, SSH_VERSION,
                                        params,
                                        private_host_key, private_server_key,
                                        blob, blob_len, NULL, NULL);

  ssh_private_key_free(private_host_key);
  ssh_private_key_free(private_server_key);
  ssh_xfree(blob);
  c->script = testcase->server_script;
  c->side = "server";
  c->name = testcase->name;

  ssh_stream_set_callback(c->stream, handler_callback, (void *)c);
  server_handler = c;
  ssh_tcp_destroy_listener(listener);
}

void connect_callback(SshIpError status, SshStream stream, void *context)
{
  Handler c;
  TestCase *testcase = context;
  SshTransportParams params;
  
  if (status != SSH_IP_OK)
    ssh_fatal("connect_callback: status %d", status);

#ifdef DEBUG
  ssh_debug("connect successful");
#endif  

  params = ssh_transport_create_params();
  update_algs(params, testcase->c_to_s_algs);
  
  c = ssh_xcalloc(sizeof(*c), 1);
  c->stream = ssh_transport_client_wrap(stream, random_state, SSH_VERSION,
                                        testcase->service, params,
                                        SERVER_NAME, NULL, NULL, NULL, NULL);
  c->script = testcase->client_script;
  c->side = "client";
  c->name = testcase->name;
  ssh_stream_set_callback(c->stream, handler_callback, (void *)c);
  client_handler = c;
}

int main(int ac, char **av)
{
  char port[100];
  int i;
  TestCase *testcase;
  int pass;
  SshTime time_now;

  time_now = ssh_time();
  srandom(time_now);

  for (pass = 0; pass < PASSES; pass++)
    {
#ifdef DEBUG
      ssh_debug("pass %d", pass);
#endif
      random_state = ssh_random_allocate();

      /* randomize it a bit */
      ssh_random_add_noise(random_state, &time_now, sizeof(time_now));

      ssh_buffer_init(&testdata);
      for (i = 0; i < 100000; i++)
        buffer_put_char(&testdata, ssh_random_get_byte(random_state));

      ssh_event_loop_initialize();

      for (i = 0; tests[i].name; i++)
        {
          testcase = &tests[i];
          end_of_script_count = 0;

#ifdef DEBUG      
          ssh_debug("Running test %s", testcase->name);
#endif
          
          snprintf(port, sizeof(port), "%d", (int)(35000 + random() % 1000));
#ifdef DEBUG
          ssh_debug("Making listener, port %s...", port);
#endif
          listener = ssh_tcp_make_listener("127.0.0.1", port,
                                              listener_callback,
                                              (void *)testcase);
          if (!listener)
            ssh_fatal("making listener failed");
#ifdef DEBUG      
          ssh_debug("Making connect...");
#endif
          ssh_tcp_connect_with_socks("127.0.0.1", port, NULL, 2,
                             connect_callback, (void *)testcase);

#ifdef DEBUG      
          ssh_debug("Event loop running...");
#endif 
          ssh_event_loop_run();
#ifdef DEBUG
          ssh_debug("Event loop exited...");
#endif
          if (end_of_script_count != 2)
            ssh_fatal("end_of_script_count %d, script end not reached.",
                  end_of_script_count);
          /* Listener was destroyed in callback. */
        }
  
      ssh_event_loop_uninitialize();
      ssh_buffer_uninit(&testdata);
      ssh_random_free(random_state);
    }
#ifdef DEBUG
  ssh_debug("Exiting...");
#endif
  return 0;
}

