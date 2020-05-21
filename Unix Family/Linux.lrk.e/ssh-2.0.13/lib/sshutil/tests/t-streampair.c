/*

t-streampair.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Test program for stream pairs.

*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshstreampair.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

SshStream ts1, ts2;
SshBuffer *testdata = NULL;
SshBuffer *received_data;
int break_test;
int test_data_index;
int destroy_count;
Boolean reader_sent_eof;

#define T_STREAMPAIR_BIG_BUF_LEN        32768

void create_testdata(void)
{
  int len, i;
  unsigned char ch;

  if (testdata)
    ssh_buffer_clear(testdata);
  else
    testdata = ssh_buffer_allocate();
  
  len = random() % 100000;
  for (i = 0; i < len; i++)
    {
      ch = random();
      ssh_buffer_append(testdata, &ch, 1);
    }
}

void copy_reader(SshStreamNotification op, void *context)
{
  unsigned char *buf;
  int len;
  
  if (op != SSH_STREAM_INPUT_AVAILABLE)
    return;

  buf = ssh_xmalloc(T_STREAMPAIR_BIG_BUF_LEN);

  for (;;)
    {
      len = ssh_stream_read(ts2, buf, T_STREAMPAIR_BIG_BUF_LEN);
      if (len == 0)
        {
          ssh_stream_destroy(ts2);
          ts2 = NULL;
          destroy_count++;
          ssh_xfree(buf);
          return; /* EOF received */
        }
      if (len < 0)
        {
          ssh_xfree(buf);
          return;
        }
      ssh_buffer_append(received_data, buf, len);
      if (break_test && random() % 10 == 0)
        {
          ssh_stream_destroy(ts2);
          ts2 = NULL;
          destroy_count++;
          ssh_xfree(buf);
          return;
        }
      if (!reader_sent_eof && random() % 10 == 0)
        {
          ssh_stream_output_eof(ts2);
          reader_sent_eof = TRUE;
        }
    }
  /*NOTREACHED*/
}

void copy_writer(SshStreamNotification op, void *context)
{
  int len;
  int len2;
  unsigned char buf[100];

  if (op != SSH_STREAM_CAN_OUTPUT)
    return;
  
  for (;;)
    {
      len = ssh_buffer_len(testdata) - test_data_index;
      len2 = random() % 100000;
      if (len <= 0)
        {
          if (random() % 2 == 0)
            ssh_stream_output_eof(ts1);
          ssh_stream_destroy(ts1);
          ts1 = NULL;
          destroy_count++;
          return;
        }
      if (len > len2)
        len = len2;
      len = ssh_stream_write(ts1, (unsigned char *)ssh_buffer_ptr(testdata) +
                             test_data_index, len);
      if (len == 0)
        {
          if (random() % 2 == 0)
            ssh_stream_output_eof(ts1);
          ssh_stream_destroy(ts1);
          ts1 = NULL;
          destroy_count++;
          return; /* Eof while writing. */
        }
      if (len < 0)
        return; /* Cannot write more at this time */
      test_data_index += len;

      if (random() % 5 == 0)
        {
          len = ssh_stream_read(ts1, buf, sizeof(buf));
          if (len == 0 && !reader_sent_eof)
            ssh_fatal("copy_writer: read returned EOF when not sent");
          if (len > 0)
            ssh_fatal("copy_writer: read > 0");
        }
    }
}

void copy_data_test(SshStream s1, SshStream s2)
{
  ts1 = s1;
  ts2 = s2;

  create_testdata();
  if (received_data)
    ssh_buffer_clear(received_data);
  else
    received_data = ssh_buffer_allocate();
  test_data_index = 0;
  destroy_count = 0;
  reader_sent_eof = FALSE;
  
  ssh_stream_set_callback(s1, copy_writer, NULL);
  ssh_stream_set_callback(s2, copy_reader, NULL);

  ssh_event_loop_run();
  if (destroy_count != 2 || ts1 != NULL || ts2 != NULL)
    ssh_fatal("copy_data_test: one stream not destroyed");
  if (ssh_buffer_len(received_data) > ssh_buffer_len(testdata))
    ssh_fatal("copy_data_test: received more data than sent");
  if (break_test)
    ssh_buffer_consume_end(testdata,
                       ssh_buffer_len(testdata) - ssh_buffer_len(received_data));
  if (ssh_buffer_len(testdata) != ssh_buffer_len(received_data))
    ssh_fatal("copy_data_test: data lens differ");
  if (memcmp(ssh_buffer_ptr(testdata), ssh_buffer_ptr(received_data),
             ssh_buffer_len(testdata)) != 0)
    ssh_fatal("copy_data_test: received data differs");
}

int main()
{
  int pass;
  SshStream s1, s2;

  srandom(ssh_time());
  
  ssh_event_loop_initialize();
  
  for (pass = 0; pass < 100; pass++)
    {
      ssh_stream_pair_create(&s1, &s2);
      break_test = random() % 2;
      copy_data_test(s1, s2);
      
      ssh_stream_pair_create(&s1, &s2);
      break_test = random() % 2;
      copy_data_test(s2, s1);
    }
  if (testdata)
    ssh_buffer_free(testdata);
  if (received_data)
    ssh_buffer_free(received_data);

  ssh_event_loop_uninitialize();
  return 0;
}
