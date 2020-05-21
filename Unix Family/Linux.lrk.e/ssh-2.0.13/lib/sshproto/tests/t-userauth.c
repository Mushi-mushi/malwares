/*

t-userauth.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Test program for the user authentication protocol.

*/

#include "sshincludes.h"
#include "sshcross.h"
#include "sshtrans.h"
#include "sshstreampair.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshauth.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"
#include "sshcipherlist.h"

#undef DEBUG
#define TEST_VERSION "t-userauth"

SshRandomState random_state;
SshPrivateKey hostkey, serverkey;
unsigned char *hostkey_blob;
unsigned int hostkey_blob_len;


void create_server_keys(SshPrivateKey *host, SshPrivateKey *server,
                        unsigned char **blob, unsigned int *len)
{
  SshPublicKey public_host_key;

#ifdef DEBUG
  ssh_debug("generating host key");
#endif
  if (ssh_private_key_generate(random_state, host,
                               SSH_CRYPTO_RSA, SSH_PKF_SIZE, 768, 
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Generating host key failed");
#ifdef DEBUG
  ssh_debug("generating server key");
#endif

  if (ssh_private_key_generate(random_state, server,
                               SSH_CRYPTO_RSA, SSH_PKF_SIZE, 512, 
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Generating server key failed");

#ifdef DEBUG  
  ssh_debug("deriving public host key blob");
#endif
  public_host_key = ssh_private_key_derive_public_key(*host);
  if (ssh_public_key_export(public_host_key, blob, len) != SSH_CRYPTO_OK)
    ssh_fatal("deriving public key blob failed");
  ssh_public_key_free(public_host_key);
}

/* Sets up a transport stream for the test.  This does not wrap an
   authentication stream around the transport streams. */

void create_test_setup(SshStream *client_return, SshStream *server_return)
{
  SshStream client, server;
  SshStream s1, s2;
  
  ssh_stream_pair_create(&s1, &s2);

  /* Initialize server side. */
  server = ssh_transport_server_wrap(s1, random_state, TEST_VERSION, NULL,
                                     hostkey, serverkey,
                                     hostkey_blob, hostkey_blob_len, 
                                     NULL, NULL);

  client = ssh_transport_client_wrap(s2, random_state, TEST_VERSION,
                                     SSH_USERAUTH_SERVICE, NULL,
                                     "localhost", NULL, NULL, NULL, NULL);

  *client_return = client;
  *server_return = server;
}

#define CORRECT_USER  "correctuser"
#define WRONG_USER    "wronguser"
#define CORRECT_PASS  "correctpass"
#define WRONG_PASS    "wrongpass"

#define PINGPONG_PACKET   SSH_FIRST_USERAUTH_METHOD_PACKET

Boolean simple_password_accept;
Boolean simple_user_accept;
Boolean simple_password_failed;
Boolean simple_password_authenticated;
Boolean simple_password_may_fail;
int pingpong_count;
Boolean pingpong_success;

SshAuthServerResult simple_password_server(SshAuthServerOperation op,
                                           const char *user,
                                           SshBuffer *packet,
                                           const unsigned char *session_id,
                                           size_t session_id_len,
                                           void **state_placeholder,
                                           void **longtime_placeholder,
                                           void *method_context)
{
  char *password;
  Boolean is_pingpong;
  SshUInt32 value;

#ifdef DEBUG
  ssh_debug("simple_password_server: op %d", (int)op);
#endif
  
  switch (op)
    {
    case SSH_AUTH_SERVER_OP_START:
      if (ssh_decode_buffer(packet,
                            SSH_FORMAT_BOOLEAN, &is_pingpong,
                            SSH_FORMAT_END) == 0)
        {
#ifdef DEBUG
          ssh_debug("simple_password_server: bad is_pingpong");
#endif
          return SSH_AUTH_SERVER_REJECTED;
        }
      if (!is_pingpong)
        {
          /* Normal password auth */
          if (pingpong_count != 0)
            ssh_fatal("simple_password_server: passwd when pingpong");
          if (ssh_decode_buffer(packet,
                                SSH_FORMAT_UINT32_STR, &password, NULL,
                                SSH_FORMAT_END) == 0)
            ssh_debug("simple_password_server: bad passwd request");
          
          if (strcmp(user, CORRECT_USER) == 0)
            {
              if (!simple_user_accept)
                ssh_fatal("simple_password_server: correct user, !accept");
            }
          else
            if (strcmp(user, WRONG_USER) == 0)
              {
                if (simple_user_accept)
                  ssh_fatal("simple_password_server: wrong user, accept");
              }
            else
              ssh_fatal("simple_password_server: bad user");
          
          if (strcmp(password, CORRECT_PASS) == 0)
            {
              if (!simple_password_accept)
                ssh_fatal("simple_password_server: correct pass, !accept");
            }
          else
            if (strcmp(password, WRONG_PASS) == 0)
              {
                if (simple_password_accept)
                  ssh_fatal("simple_password_server: wrong pass, accept");
              }
            else
              ssh_fatal("simple_password_server: bad pass");
          
          if (strcmp(user, CORRECT_USER) == 0 &&
              strcmp(password, CORRECT_PASS) == 0)
            {
              ssh_xfree(password);
#ifdef DEBUG
              ssh_debug("simple_password_server: accepted");
#endif
              return SSH_AUTH_SERVER_ACCEPTED;
            }
          
          ssh_xfree(password);
#ifdef DEBUG
          ssh_debug("simple_password_server: rejected");
#endif
          return SSH_AUTH_SERVER_REJECTED;
        }
      else
        {
          /* Pingpong request. */
          if (pingpong_count == 0)
            ssh_fatal("simple_password_server: pingpong when count 0");
          if (ssh_decode_buffer(packet,
                                SSH_FORMAT_UINT32, &value,
                                SSH_FORMAT_END) == 0)
            ssh_fatal("simple_password_server: bad pingpong");
          if (value == pingpong_count)
            {
#ifdef DEBUG
              ssh_debug("simple_password_server: pingpong count reached");
#endif
              return SSH_AUTH_SERVER_ACCEPTED;
            }
          *state_placeholder = (void *)value;
          value ^= 0x12345678;
          ssh_buffer_clear(packet);
          ssh_encode_buffer(packet,
                            SSH_FORMAT_CHAR, (unsigned int) PINGPONG_PACKET,
                            SSH_FORMAT_UINT32, value,
                            SSH_FORMAT_END);
          return SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK;
        }
      /*NOTREACHED*/
      abort();

    case SSH_AUTH_SERVER_OP_ABORT:
#ifdef DEBUG
      ssh_debug("simple_password_server: SERVER_OP_ABORT");
#endif
      *state_placeholder = NULL;
      return SSH_AUTH_SERVER_REJECTED;

    case SSH_AUTH_SERVER_OP_CONTINUE:
#ifdef DEBUG
      ssh_debug("simple_password_server: SERVER_OP_CONTINUE");
#endif
      if (ssh_decode_buffer(packet,
                            SSH_FORMAT_BOOLEAN, &is_pingpong,
                            SSH_FORMAT_UINT32, &value,
                            SSH_FORMAT_END) == 0)
        ssh_fatal("simple_password_server: bad pingpong continue");
      if (!is_pingpong)
        ssh_fatal("simple_password_server: !pingpong");
      if (((SshUInt32)*state_placeholder) + 1 != value)
        ssh_fatal("simple_password_server: pingpong did not +1");
      if (value == pingpong_count)
        {
#ifdef DEBUG
          ssh_debug("simple_password_server: pingpong count reached");
#endif
          *state_placeholder = NULL;
          pingpong_success = TRUE;
          return SSH_AUTH_SERVER_ACCEPTED;
        }
      *state_placeholder = (void *)value;
      value ^= 0x12345678;
      ssh_buffer_clear(packet);
      ssh_encode_buffer(packet,
                        SSH_FORMAT_CHAR, (unsigned int) PINGPONG_PACKET,
                        SSH_FORMAT_UINT32, value,
                        SSH_FORMAT_END);
      return SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK;

    case SSH_AUTH_SERVER_OP_UNDO_LONGTIME:
#ifdef DEBUG
      ssh_debug("simple_password_server: SERVER_OP_UNDO_LONGTIME");
#endif
      return SSH_AUTH_SERVER_REJECTED;

    case SSH_AUTH_SERVER_OP_CLEAR_LONGTIME:
#ifdef DEBUG
      ssh_debug("simple_password_server: SERVER_OP_CLEAR_LONGTIME");
#endif
      return SSH_AUTH_SERVER_REJECTED;

    default:
      ssh_fatal("simple_password_server: unknown op %d", (int)op);
    }
  /*NOTREACHED*/
  return SSH_AUTH_SERVER_REJECTED;
}

typedef struct ClientPingPongDataRec
{
  SshUInt32 count;
} ClientPingPongData;

void simple_password_client(SshAuthClientOperation op,
                            const char *user,
                            unsigned int packet_type,
                            SshBuffer *packet_in,
                            const unsigned char *session_id,
                            size_t session_id_len,
                            void **state_placeholder,
                            SshAuthClientCompletionProc completion_proc,
                            void *completion_context,
                            void *method_context)
{
  char *pass;
  SshBuffer *b;
  ClientPingPongData *pd;
  SshUInt32 value;

#ifdef DEBUG
  ssh_debug("simple_password_client: op %d", (int)op);
#endif  

  switch (op)
    {
    case SSH_AUTH_CLIENT_OP_START:

      simple_user_accept = random() % 2;
      simple_password_accept = random() % 2;
      
      if (simple_password_may_fail && pingpong_success &&
          random() % 5 == 0)
        {
#ifdef DEBUG
          ssh_debug("simple_password_client: cancelling");
#endif
          simple_password_failed = TRUE;
          (*completion_proc)(SSH_AUTH_CLIENT_CANCEL, user, NULL,
                             completion_context);
          return;
        }
      
      if (simple_user_accept)
        user = CORRECT_USER;
      else
        user = WRONG_USER;
      if (simple_password_accept)
        pass = CORRECT_PASS;
      else
        pass = WRONG_PASS;

      b = ssh_buffer_allocate();

      if (pingpong_count > 0)
        {
          /* Send pingpong reply */
          assert(*state_placeholder == NULL);
          pd = ssh_xmalloc(sizeof(*pd));
          *state_placeholder = pd;
          pd->count = 0;
#ifdef DEBUG
          ssh_debug("simple_password_client: sending pongpong %ld", pd->count);
#endif
          ssh_encode_buffer(b,
                            SSH_FORMAT_BOOLEAN, TRUE,
                            SSH_FORMAT_UINT32, pd->count,
                            SSH_FORMAT_END);
          if (pd->count < pingpong_count)
            (*completion_proc)(SSH_AUTH_CLIENT_SEND_AND_CONTINUE, user, b,
                               completion_context);
          else
            {
              ssh_xfree(*state_placeholder);
              *state_placeholder = NULL;
              (*completion_proc)(SSH_AUTH_CLIENT_SEND, user, b,
                                 completion_context);
            }
        }
      else
        {
          /* Send normal reply */
#ifdef DEBUG
          ssh_debug("simple_password_client: sending req");
#endif
          ssh_encode_buffer(b,
                            SSH_FORMAT_BOOLEAN, FALSE,
                            SSH_FORMAT_UINT32_STR, pass, strlen(pass),
                            SSH_FORMAT_END);
          (*completion_proc)(SSH_AUTH_CLIENT_SEND, user, b,
                             completion_context);
        }
      ssh_buffer_free(b);
      break;
      
    case SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE:
#ifdef DEBUG
      ssh_debug("simple_password_client: noninteractive failing");
#endif
      (*completion_proc)(SSH_AUTH_CLIENT_FAIL, user, NULL, completion_context);
      break;
      
    case SSH_AUTH_CLIENT_OP_CONTINUE:
#ifdef DEBUG
      ssh_debug("simple_password_client: OP_CONTINUE");
#endif
      pd = *state_placeholder;
      if (pd == NULL || pd->count < 0 || pd->count >= pingpong_count)
        ssh_fatal("simple_password_client: strange pd");
      if (ssh_decode_buffer(packet_in,
                            SSH_FORMAT_UINT32, &value,
                            SSH_FORMAT_END) == 0)
        ssh_fatal("simple_password_client: bad packet_in");
      if ((value ^ 0x12345678) != pd->count)
        ssh_fatal("simple_password_client: bad value");
      pd->count++;
#ifdef DEBUG
      ssh_debug("simple_password_client: sending pongpong %ld", pd->count);
#endif
      b = ssh_buffer_allocate();
      ssh_encode_buffer(b,
                        SSH_FORMAT_BOOLEAN, TRUE,
                        SSH_FORMAT_UINT32, pd->count,
                        SSH_FORMAT_END);
      if (pd->count < pingpong_count)
        (*completion_proc)(SSH_AUTH_CLIENT_SEND_AND_CONTINUE, user, b,
                           completion_context);
      else
        {
          ssh_xfree(*state_placeholder);
          *state_placeholder = NULL;
          (*completion_proc)(SSH_AUTH_CLIENT_SEND, user, b,
                             completion_context);
        }
      ssh_buffer_free(b);
      break;
      
    case SSH_AUTH_CLIENT_OP_ABORT:
      if (*state_placeholder)
        {
          ssh_xfree(*state_placeholder);
          *state_placeholder = NULL;
        }
      break;
      
    default:
      ssh_fatal("simple_password_client: unknown op %d", (int)op);
    }
}

SshAuthServerResult serveronly_server(SshAuthServerOperation op,
                                      const char *user,
                                      SshBuffer *packet,
                                      const unsigned char *session_id,
                                      size_t session_id_len,
                                      void **state_placeholder,
                                      void **longtime_placeholder,
                                      void *method_context)
{
  if (op == SSH_AUTH_SERVER_OP_UNDO_LONGTIME ||
      op == SSH_AUTH_SERVER_OP_CLEAR_LONGTIME)
    return SSH_AUTH_SERVER_REJECTED;
  ssh_fatal("serveronly_server called");
  /*NOTREACHED*/
  return SSH_AUTH_SERVER_REJECTED;
}

void clientonly_client(SshAuthClientOperation op,
                       const char *user,
                       unsigned int packet_type,
                       SshBuffer *packet_in,
                       const unsigned char *session_id,
                       size_t session_id_len,
                       void **state_placeholder,
                       SshAuthClientCompletionProc completion_proc,
                       void *completion_context,
                       void *method_context)
{
  switch (op)
    {
    case SSH_AUTH_CLIENT_OP_START_NONINTERACTIVE:
      /* This can get called even for client-only methods, as we call this
         method "blind" without knowing whether the server supports it. */
      break;
    case SSH_AUTH_CLIENT_OP_START:
    case SSH_AUTH_CLIENT_OP_CONTINUE:
    case SSH_AUTH_CLIENT_OP_ABORT:
    default:
      ssh_fatal("clientonly_client called op %d", (int)op);
    }
}

SshAuthServerMethod simple_server_methods[] =
{
  { "password1", simple_password_server },
  { "password2", simple_password_server },
  { "serveronly", serveronly_server },
  { NULL }
};

SshAuthClientMethod simple_client_methods[] =
{
  { "password1", simple_password_client },
  { "password2", simple_password_client },
  { "clientonly", clientonly_client },
  { NULL }
};

void simple_password_create(SshStream *client_return, SshStream *server_return,
                            SshAuthPolicyProc policy_proc)
{
  SshStream client_tr, server_tr;

  create_test_setup(&client_tr, &server_tr);

  *client_return = ssh_auth_client_wrap(client_tr, "", "TEST",
                                        simple_client_methods, NULL);
  *server_return = ssh_auth_server_wrap(server_tr, policy_proc, NULL,
                                        simple_server_methods, NULL);
}

void disconnect_test()
{
  SshStream server;
  SshStream s1, s2;
  unsigned char buf[8192];
  int len, i;
  
  ssh_stream_pair_create(&s1, &s2);

  /* Initialize server side. */
  server = ssh_transport_server_wrap(s1, random_state, TEST_VERSION, NULL,
                                     hostkey, serverkey,
                                     hostkey_blob, hostkey_blob_len,
                                     NULL, NULL);

  ssh_event_loop_run();
  
  if (random() % 5 == 0)
    len = 0;
  else
    len = random() % sizeof(buf);
  for (i = 0; i < len; i++)
    {
      buf[i] = random();
      if (buf[i] < 32 && buf[i] != '\n' && buf[i] != '\r')
        buf[i] = 'X';
    }

  ssh_stream_write(s2, buf, len);

  ssh_event_loop_run();

  ssh_stream_destroy(s2);

  ssh_event_loop_run();

  ssh_stream_destroy(server);

  ssh_event_loop_run();
}

  

SshCrossDown client_down, server_down;

void client_received_packet(SshCrossPacketType type,
                            const unsigned char *data, size_t len,
                            void *context)
{
#ifdef DEBUG
  switch (type)
    {
    case SSH_CROSS_PACKET:
      ssh_debug("client_received_packet: PACKET");
      break;
    case SSH_CROSS_DISCONNECT:
      ssh_debug("client_received_packet: DISCONNECT");
      simple_password_failed = TRUE;
      break;
    case SSH_CROSS_DEBUG:
      ssh_debug("client_received_packet: DEBUG");
      break;
    case SSH_CROSS_STARTUP:
      ssh_debug("client_received_packet: STARTUP");
      break;
    case SSH_CROSS_ALGORITHMS:
      ssh_debug("client_received_packet: ALGORITHMS");
      break;
    case SSH_CROSS_AUTHENTICATED:
      ssh_debug("client_received_packet: AUTHENTICATED");
      simple_password_authenticated = TRUE;
      break;
    default:
      ssh_fatal("client_received_packet: type %d", (int)type);
    }
#endif
}

void server_received_packet(SshCrossPacketType type,
                            const unsigned char *data, size_t len,
                            void *context)
{
  char *service;

  switch (type)
    {
    case SSH_CROSS_PACKET:
#ifdef DEBUG
      ssh_debug("server_received_packet: PACKET");
#endif
      break;
    case SSH_CROSS_DISCONNECT:
#ifdef DEBUG
      ssh_debug("server_received_packet: DISCONNECT");
#endif
      /* XXX destroy? */
      break;
    case SSH_CROSS_DEBUG:
#ifdef DEBUG
      ssh_debug("server_received_packet: DEBUG");
#endif
      break;
    case SSH_CROSS_STARTUP:
#ifdef DEBUG
      ssh_debug("server_received_packet: STARTUP");
#endif
      break;
    case SSH_CROSS_ALGORITHMS:
#ifdef DEBUG
      ssh_debug("server_received_packet: ALGORITHMS");
#endif
      break;
    case SSH_CROSS_AUTHENTICATED:
#ifdef DEBUG
      ssh_debug("server_received_packet: AUTHENTICATED");
#endif
      break;

    case SSH_CROSS_SERVICE_REQUEST:
#ifdef DEBUG
      ssh_debug("server_received_packet: SERVICE_REQUEST");
#endif
      if (ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR, &service, NULL,
                           SSH_FORMAT_END) == 0)
        ssh_fatal("server_received_packet: bad service request");
      if (strcmp(service, "TEST") == 0)
        ssh_cross_down_send(server_down, SSH_CROSS_SERVICE_ACCEPT, NULL, 0);
      else
        ssh_cross_down_send_disconnect(server_down, TRUE,
                                       SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                                       "Service not available");
      ssh_xfree(service);
      break;
                                 
    default:
      ssh_fatal("server_received_packet: type %d", (int)type);
    }
}

void simple_password_test(SshAuthPolicyProc policy_proc)
{
  SshStream client, server;

  simple_password_create(&client, &server, policy_proc);

  client_down = ssh_cross_down_create(client, client_received_packet,
                                      NULL, NULL, NULL);
  ssh_cross_down_can_receive(client_down, TRUE);
  server_down = ssh_cross_down_create(server, server_received_packet,
                                      NULL, NULL, NULL);
  ssh_cross_down_can_receive(server_down, TRUE);

  simple_password_failed = FALSE;
  simple_password_authenticated = FALSE;
  simple_password_may_fail = random() % 2;
  if (!pingpong_success || random() % 3 == 0)
    pingpong_count = random() % 5;
  else
    pingpong_count = 0;

  ssh_event_loop_run();

  if ((!simple_password_failed && !simple_password_authenticated) ||
      (simple_password_failed && simple_password_authenticated))
    ssh_fatal("simple_password_test: exited without fail/auth");

  if (!simple_password_may_fail && simple_password_failed)
    ssh_fatal("simple_pasword_test: failed without permission");
  
  switch (random() % 4)
    {
    case 0:
      ssh_cross_down_destroy(client_down);
      ssh_event_loop_run();
      ssh_cross_down_destroy(server_down);
      break;
    case 1:
      ssh_cross_down_destroy(server_down);
      ssh_event_loop_run();
      ssh_cross_down_destroy(client_down);
      break;
    case 2:
      ssh_cross_down_destroy(server_down);
      ssh_cross_down_destroy(client_down);
      break;
    case 3:
      ssh_cross_down_destroy(client_down);
      ssh_cross_down_destroy(server_down);
      break;
    default:
      abort();
    }
  ssh_event_loop_run();
}

char *dual_policy(const char *user, const char *service, const char *client_ip,
                  const char *client_port,
                  const char *completed_authentications, void *context)
{
#ifdef DEBUG
  ssh_debug("dual_policy: user '%s' service '%s' client_ip '%s' "
            "client_port '%s' completed '%s'",
            user, service, client_ip, client_port, completed_authentications);
#endif

  if (strcmp(completed_authentications, "") == 0)
    return ssh_xstrdup("password1");
  if (strcmp(completed_authentications, "password1") == 0)
    return ssh_xstrdup("password2");
  if (strcmp(completed_authentications, "password2") == 0)
    return ssh_xstrdup("password1");
  if (strcmp(completed_authentications, "password1,password2") == 0 ||
      strcmp(completed_authentications, "password2,password1") == 0)
    return NULL;
  return "";
}

int main()
{
  int pass;

  srandom(ssh_time());

  ssh_event_loop_initialize();
  
  random_state = ssh_random_allocate();
  create_server_keys(&hostkey, &serverkey, &hostkey_blob, &hostkey_blob_len);

  pingpong_success = FALSE;
  for (pass = 0; pass < 10; pass++)
    {
#ifdef DEBUG
      ssh_debug("========== iteration %d ==========", pass);
#endif
      disconnect_test();
      simple_password_test(NULL);
    }
  if (!pingpong_success)
    ssh_fatal("main: no successful pingpong");

  pingpong_success = FALSE;
  
  for (pass = 0; pass < 100; pass++)
    {
#ifdef DEBUG
      ssh_debug("========== iteration dual-%d ==========", pass);
#endif
      disconnect_test();
      simple_password_test(dual_policy);
    }

  if (!pingpong_success)
    ssh_fatal("main: no successful pingpong");
  
  ssh_private_key_free(hostkey);
  ssh_private_key_free(serverkey);
  ssh_xfree(hostkey_blob);
  ssh_random_free(random_state);

  ssh_event_loop_uninitialize();
  return 0;
}

/* XXX test REJECT_WITH_PACKET_BACK (eg. evenp auth method) */
