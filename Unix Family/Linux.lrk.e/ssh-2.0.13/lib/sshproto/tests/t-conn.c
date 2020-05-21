/*

t-conn.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Tests for the SSH connection protocol.

*/

/* XXX test stderr transfer */

#include "sshincludes.h"
#include "sshstreampair.h"
#include "sshbuffer.h"
#include "sshconn.h"
#include "sshencode.h"
#include "sshmsgs.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

SshConn test_c1, test_c2;

SshBuffer data_source, data_received;
SshBuffer stderr_source, stderr_received;
int source_channel_id, target_channel_id;
int channel_destroy_count;
Boolean test_ok;
SshStream source_stream, target_stream;
int source_offset;
Boolean target_eof_received;
Boolean request_done;

typedef enum
{
  EXPECT_AUTHENTICATED = 0,
  EXPECT_DISCONNECT,
  EXPECT_CHANNEL_OPEN,
  EXPECT_CHANNEL_OPEN_FAILURE,
  EXPECT_CHANNEL_REQUEST,
  EXPECT_CHANNEL_REQUEST_FAILURE,
  EXPECT_CHANNEL_DESTROY,
  EXPECT_GLOBAL,
  EXPECT_GLOBAL_FAILURE
} ConnExpect;

const char conn_expect_name[][80] = 
{
  "EXPECT_AUTHENTICATED",
  "EXPECT_DISCONNECT",
  "EXPECT_CHANNEL_OPEN",
  "EXPECT_CHANNEL_OPEN_FAILURE",
  "EXPECT_CHANNEL_REQUEST",
  "EXPECT_CHANNEL_REQUEST_FAILURE",
  "EXPECT_CHANNEL_DESTROY",
  "EXPECT_GLOBAL",
  "EXPECT_GLOBAL_FAILURE"
};

ConnExpect expect;

void test_source_callback(SshStreamNotification op, void *context)
{
  int len;
  unsigned char *cp;

  if (context != (void *)30)
    ssh_fatal("test_source_callback: bad context");

  if (op != SSH_STREAM_CAN_OUTPUT)
    return;

  if (expect == EXPECT_CHANNEL_REQUEST ||
      expect == EXPECT_CHANNEL_REQUEST_FAILURE)
    if (!request_done)
      return;
  
  if (source_offset >= ssh_buffer_len(&data_source))
    return;

  while (source_offset < ssh_buffer_len(&data_source))
    {
      len = ssh_buffer_len(&data_source) - source_offset;
      cp = ssh_buffer_ptr(&data_source);
      len = ssh_stream_write(source_stream, cp + source_offset, len);
      if (len <= 0)
        return;
      source_offset += len;
   }

  if (expect == EXPECT_CHANNEL_DESTROY)
    {
      if (source_offset > ssh_buffer_len(&data_source) / 2)
        {
          if (source_channel_id != -1)
            ssh_conn_channel_close(test_c1, source_channel_id);
          source_channel_id = -1;
          return;
        }
    }
  
  if (source_offset == ssh_buffer_len(&data_source))
    {
      ssh_stream_output_eof(source_stream);
      if (source_channel_id != -1)
        ssh_conn_channel_close(test_c1, source_channel_id);
      source_channel_id = -1;
    }
}

void test_target_callback(SshStreamNotification op, void *context)
{
  char buf[8192];
  int len;
  
  if (context != (void *)40)
    ssh_fatal("test_target_callback: bad context");

  if (op != SSH_STREAM_INPUT_AVAILABLE)
    return;

  for (;;)
    {
      len = ssh_stream_read(target_stream, buf, sizeof(buf));
      if (len < 0)
        return;
      if (len == 0)
        {
          target_eof_received = TRUE;
          return;
        }
      ssh_buffer_append(&data_received, buf, len);
    }
}

void test_disconnect(int reason, const char *msg, void *context)
{
  if (expect != EXPECT_DISCONNECT)
    ssh_fatal("test_disconnect: not expecting disconnect");
  if (context != (void *)1)
    ssh_fatal("test_disconnect: unexpected for non-1");
  test_ok = TRUE;
}

void test_debug(int type, const char *msg, void *context)
{
#ifdef DBEUG
  printf("test_debug: %s\n", msg);
#endif
}

void test_special(SshCrossPacketType type,
                  const unsigned char *data, size_t len,
                  void *context)
{
  if (expect != EXPECT_AUTHENTICATED)
    ssh_fatal("test_special: expected AUTHENTICATED");

  /* We shouldn't receive other packet types here now, but if we change the
     test to use the real transport/userauth layers, we'll also receive
     other special packets. */
  if (type != SSH_CROSS_AUTHENTICATED)
    ssh_fatal("test_special: packet not AUTHENTICATED");
  test_ok = TRUE;
}

void test_channel_request_cb(Boolean success,
                             const unsigned char *data,
                             size_t len,
                             void *context)
{
  if (context != (void *)20)
    ssh_fatal("test_channel_request_cb: bad context");

  /* XXX cannot send data in request reply yet! */
  if (expect == EXPECT_CHANNEL_REQUEST)
    {
      if (!success)
        ssh_fatal("test_channel_request_cb: REQUEST and !success");
    }
  else
    {
      if (success)
        ssh_fatal("test_channel_request_cb: REQUEST_FAILURE and success");
    }
  request_done = TRUE;
  test_source_callback(SSH_STREAM_CAN_OUTPUT, (void *)30);
  test_ok = TRUE;
}

Boolean test_channel_request(const char *type, const unsigned char *data,
                             size_t len, void *context)
{
  if (expect != EXPECT_CHANNEL_REQUEST &&
      expect != EXPECT_CHANNEL_REQUEST_FAILURE)
    ssh_fatal("test_channel_request: unexpect CHANNEL_REQUEST");
  if ((int)context == 0)
    {
      if (strcmp(type, "testrequest1") != 0)
        ssh_fatal("test_channel_request: unexpected channel req type 1");
      if (len != 4 || memcmp(data, "REQ1", 4) != 0)
        ssh_fatal("test_channel_request: bad data 1");
      if (expect == EXPECT_CHANNEL_REQUEST)
        return TRUE;
      else
        return FALSE;
    }
  else
    { /* Send back another channel request. We are c2. */
      if (strcmp(type, "testrequest0") != 0)
        ssh_fatal("test_channel_request: unexpected channel req type 0");
      if (len != 4 || memcmp(data, "REQ0", 4) != 0)
        ssh_fatal("test_channel_request: bad data 0");
      ssh_conn_send_channel_request(test_c2, target_channel_id,
                                    "testrequest1", "REQ1", 4,
                                    test_channel_request_cb,
                                    (void *)20);
      return TRUE;
    }
}

void test_channel_destroy(void *context)
{
  if (expect != EXPECT_CHANNEL_DESTROY &&
      expect != EXPECT_CHANNEL_OPEN &&
      expect != EXPECT_CHANNEL_OPEN_FAILURE &&
      expect != EXPECT_CHANNEL_REQUEST &&
      expect != EXPECT_CHANNEL_REQUEST_FAILURE &&
      expect != EXPECT_CHANNEL_DESTROY)
    ssh_fatal("test_channel_destroy: not expecting DESTROY");
  channel_destroy_count++;
  if (channel_destroy_count > 2)
    ssh_fatal("test_channel_destroy: too many destroys");
  if (channel_destroy_count == 2)
    {
      if (expect == EXPECT_CHANNEL_OPEN ||
          expect == EXPECT_CHANNEL_REQUEST ||
          expect == EXPECT_CHANNEL_REQUEST_FAILURE)
        {
          if (context == (void *)1)
            {
              if (!target_eof_received)
                ssh_fatal("test_channel_destroy: !target_eof_received");
              if (ssh_buffer_len(&data_received) != ssh_buffer_len(&data_source))
                ssh_fatal("test_channel_destroy: not all data received");
              if (memcmp(ssh_buffer_ptr(&data_source), ssh_buffer_ptr(&data_received),
                         ssh_buffer_len(&data_source)) != 0)
                ssh_fatal("test_channel_destroy: received data differs");
            }
          else
            {
              if (source_offset != ssh_buffer_len(&data_source))
                ssh_fatal("test_channel_destroy: some data not sent");
            }
        }
      test_ok = TRUE;
    }

  if (context == (void *)0)
    {
      ssh_stream_destroy(source_stream);
      source_stream = NULL;
    }
  else
    {
      ssh_stream_destroy(target_stream);
      target_stream = NULL;
    }
}

Boolean test_global_request(const char *type,
                         const unsigned char *data, size_t len,
                         void *context)
{
  if (expect != EXPECT_GLOBAL &&
      expect != EXPECT_GLOBAL_FAILURE)
    ssh_fatal("test_global_request called unexpectedly");

  if (strcmp(type, "global0") != 0)
    ssh_fatal("test_global_request: bad type");
  if (len != 7 || memcmp(data, "GLOBAL0", 7) != 0)
    ssh_fatal("test_global_request: bad data");
  if (expect == EXPECT_GLOBAL)
    return TRUE;
  else
    return FALSE;
}

void test_channel_open(const char *type, int channel_id,
                       const unsigned char *data, size_t len,
                       SshConnOpenCompletionProc completion,
                       void *completion_context,
                       void *context)
{
  if (expect != EXPECT_CHANNEL_OPEN &&
      expect != EXPECT_CHANNEL_OPEN_FAILURE &&
      expect != EXPECT_CHANNEL_REQUEST &&
      expect != EXPECT_CHANNEL_REQUEST_FAILURE &&
      expect != EXPECT_CHANNEL_DESTROY)
    ssh_fatal("test_channel_open: unexpect CHANNEL_OPEN");

  if (strcmp(type, "open0") != 0)
    ssh_fatal("test_channel_open: bad type");

  if (len != 5 || memcmp(data, "DATA0", 5) != 0)
    ssh_fatal("test_channel_open: bad data");

  if (expect != EXPECT_CHANNEL_OPEN_FAILURE)
    {
      SshStream s1, s2;

      ssh_stream_pair_create(&s1, &s2);
      target_channel_id = channel_id;
      target_stream = s2;
      ssh_stream_set_callback(target_stream, test_target_callback,
                              (void *)40);
      ssh_stream_output_eof(target_stream);
      (*completion)(SSH_OPEN_OK,
                    s1, TRUE, FALSE, 5000, "TEST1", 5, test_channel_request,
                    test_channel_destroy, context, completion_context);
    }
  else
    {
      (*completion)(SSH_OPEN_CONNECT_FAILED,
                    NULL, FALSE, FALSE, 0, NULL, 0, NULL, NULL, NULL,
                    completion_context);
    }
}

SshConnGlobalRequest test_requests[] =
{
  { "global0", test_global_request },
  { "global1", test_global_request },
  { NULL, NULL }
};

SshConnChannelOpen test_opens[] =
{
  { "open0", test_channel_open },
  { "open1", test_channel_open },
  { NULL, NULL }
};

void conn_create(SshConn *c1, SshConn *c2)
{
  
  SshStream s1, s2;
  SshBuffer buffer;
  const char *user = "foo", *service = SSH_CONNECTION_SERVICE;
  int len;

  ssh_stream_pair_create(&s1, &s2);

  /* XXX this is a kludge!  We assume we can write something to the stream
     pair and have it safely buffered there!  This may fail with future
     versions of stream pairs. */
  ssh_buffer_init(&buffer);
 
  ssh_cross_encode_packet(&buffer, SSH_CROSS_AUTHENTICATED,
                          SSH_FORMAT_UINT32_STR, user, strlen(user),
                          SSH_FORMAT_UINT32_STR, service, strlen(service),
                          SSH_FORMAT_END);

  len = ssh_stream_write(s1, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  if (len != ssh_buffer_len(&buffer))
    ssh_fatal("basic_conn_test: pipe write kludge failed");
  len = ssh_stream_write(s2, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  if (len != ssh_buffer_len(&buffer))
    ssh_fatal("basic_conn_test: pipe write kludge failed");
  ssh_buffer_uninit(&buffer);

  *c1 = ssh_conn_wrap(s1, service,
                      test_requests,
                      test_opens,
                      test_disconnect,
                      test_debug,
                      test_special,
                      (void *)0);

  *c2 = ssh_conn_wrap(s2, service,
                      test_requests,
                      test_opens,
                      test_disconnect,
                      test_debug,
                      test_special,
                      (void *)1);
}

void expect_open_callback(int result, int channel_id,
                          const unsigned char *data, size_t len,
                          void *context)
{
  Boolean success = result == SSH_OPEN_OK;
  if (context != (void *)10)
    ssh_fatal("expect_open_callback: bad context");

  if (!success)
    {
      if (expect != EXPECT_CHANNEL_OPEN_FAILURE)
        ssh_fatal("expect_open_callback: not expecting open failure");
      test_ok = TRUE;
      return;
    }
  
  if (expect != EXPECT_CHANNEL_OPEN &&
      expect != EXPECT_CHANNEL_REQUEST &&
      expect != EXPECT_CHANNEL_REQUEST_FAILURE &&
      expect != EXPECT_CHANNEL_DESTROY)
    ssh_fatal("expect_open_callback: not opening channel");

  if (len != 5 || memcmp(data, "TEST1", 5) != 0)
    ssh_fatal("expect_open_callback: data mismatch");

  source_channel_id = channel_id;

  if (expect == EXPECT_CHANNEL_REQUEST ||
      expect == EXPECT_CHANNEL_REQUEST_FAILURE)
    ssh_conn_send_channel_request(test_c1, source_channel_id,
                                  "testrequest0", "REQ0", 4,
                                  NULL, NULL);
}

void expect_global_callback(Boolean success, void *context)
{
  if (context != (void *)20)
    ssh_fatal("expect_global_callback: bad context");
  
  if (expect == EXPECT_GLOBAL)
    {
      if (!success)
        ssh_fatal("expect_global_callback: GLOBAL and !success");
      test_ok = TRUE;
      return;
    }
  if (expect == EXPECT_GLOBAL_FAILURE)
    {
      if (success)
        ssh_fatal("expect_global_callback: GLOBAL_FAILURE and success");
      test_ok = TRUE;
      return;
    }
  ssh_fatal("expect_global_callback: not expecting global callback");
}

void test_expect(ConnExpect exp)
{
  SshStream s1, s2;

  expect = exp;

  /*  ssh_debug("-- test_expect(%s) --", conn_expect_name[exp]); */

  switch (expect)
    {
    case EXPECT_AUTHENTICATED:
      break;
    case EXPECT_DISCONNECT:
      ssh_conn_destroy(test_c1);
      break;

    case EXPECT_CHANNEL_OPEN:
    case EXPECT_CHANNEL_OPEN_FAILURE:
    case EXPECT_CHANNEL_REQUEST:
    case EXPECT_CHANNEL_REQUEST_FAILURE:
    case EXPECT_CHANNEL_DESTROY:
      if (source_stream != NULL || target_stream != NULL)
        ssh_fatal("test_expect: channel: source 0x%lx target 0x%lx",
                  (long)source_stream, (long)target_stream);

      request_done = FALSE;
      ssh_stream_pair_create(&s1, &s2);
      source_stream = s1;
      source_offset = 0;
      ssh_buffer_clear(&data_received);
      target_eof_received = FALSE;
      channel_destroy_count = 0;
      ssh_stream_set_callback(source_stream, test_source_callback,
                              (void *)30);
      ssh_conn_send_channel_open(test_c1, "open0", s2, TRUE, FALSE, 10000,
                                 10000,
                                 "DATA0", (size_t)5,
                                 test_channel_request, test_channel_destroy,
                                 (void *)0,
                                 expect_open_callback, (void *)10);
      break;

    case EXPECT_GLOBAL:
    case EXPECT_GLOBAL_FAILURE:
      ssh_conn_send_global_request(test_c1, "global0", "GLOBAL0", 7,
                                   expect_global_callback, (void *)20);
      break;

    default:
      ssh_fatal("test_expect: unknown expect %d", (int)exp);
    }

  test_ok = FALSE;
  ssh_event_loop_run();
  if (!test_ok)
    ssh_fatal("test_expect: did not receive test_ok");

  /* Perform expect-specific completion tests. */
  switch (expect)
    {
    case EXPECT_CHANNEL_OPEN_FAILURE:
      if (channel_destroy_count != 1)
        ssh_fatal("test_expect: destroy not called for CHANNEL_OPEN_FAILURE");
      break;
    default:
      break;
    }
}

void basic_conn_test()
{
  conn_create(&test_c1, &test_c2);
  test_expect(EXPECT_AUTHENTICATED);
  test_expect(EXPECT_CHANNEL_OPEN);
  test_expect(EXPECT_CHANNEL_OPEN_FAILURE);
  test_expect(EXPECT_CHANNEL_REQUEST);
  test_expect(EXPECT_CHANNEL_REQUEST_FAILURE);
  test_expect(EXPECT_CHANNEL_DESTROY);
  test_expect(EXPECT_GLOBAL);
  test_expect(EXPECT_GLOBAL_FAILURE);
  test_expect(EXPECT_DISCONNECT);
}

int main()
{
  int pass;
  int i, len;
  unsigned char ch;

  srandom(ssh_time());

  ssh_event_loop_initialize();

  ssh_buffer_init(&data_source);
  ssh_buffer_init(&data_received);
  ssh_buffer_init(&stderr_source);
  ssh_buffer_init(&stderr_received);

  len = random() % 100000;
  for (i = 0; i < len; i++)
    {
      ch = random();
      ssh_buffer_append(&data_source, &ch, 1);
    }
  len = random() % 100000;
  for (i = 0; i < len; i++)
    {
      ch = random();
      ssh_buffer_append(&stderr_source, &ch, 1);
    }
  
  for (pass = 0; pass < 100; pass++)
    {
      basic_conn_test();
    }

  ssh_buffer_uninit(&data_source);
  ssh_buffer_uninit(&data_received);
  ssh_buffer_uninit(&stderr_source);
  ssh_buffer_uninit(&stderr_received);

  ssh_event_loop_uninitialize();

  /* ssh_debug("-- end of t-conn --"); */

  return 0;
}
