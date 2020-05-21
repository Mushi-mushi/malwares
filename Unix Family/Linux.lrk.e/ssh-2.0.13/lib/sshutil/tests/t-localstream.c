/*

t-localstream.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Sat Apr 18 11:57:24 EEST 1998

*/

/*
 * $Id: t-localstream.c,v 1.3 1998/05/24 01:47:04 kivinen Exp $
 * $Log: t-localstream.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "sshlocalstream.h"
#include "sshunixeloop.h"

#ifdef WINDOWS
#define random()  rand()
#endif /* WINDOWS */
#define PASSES 200

int exited1 = 0, exited2 = 0;
SshLocalListener listener1, listener2;
SshStreamStats stats;
SshBuffer send_buffer, expect_buffer;
unsigned long send_count = 0, read_count = 0;

char lpath1[0x100];
char lpath2[0x100];

void server1_read(SshStream stream)
{
  int ret;
  unsigned char buf[1024];

  for (;;)
    {
      ret = ssh_stream_read(stream, buf, sizeof(buf));
      if (ret < 0)
	return;
      if (ret == 0)
	{
	  if (read_count != send_count)
	    ssh_fatal("server1_read eof received, read_count %ld send_count %ld",
		  read_count, send_count);
	  break;
	}
      if (memcmp(buf, ssh_buffer_ptr(&expect_buffer), ret) != 0)
	ssh_fatal("server1_read data does not match");
      ssh_buffer_consume(&expect_buffer, ret);
      read_count += ret;
    }
  /* All data has been received. */
  ssh_stream_destroy(stream);
  exited1 = 1;
}

void server1_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = context;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      server1_read(stream);
      break;
    case SSH_STREAM_CAN_OUTPUT:
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("server1_callback: received disconnect");
    default:
      ssh_fatal("server1_callback notification %d", notification);
    }
}

void listener1_callback(SshStream stream, void *context)
{
  if (!stream)
    ssh_fatal("listener1 have no stream");

  ssh_stream_set_callback(stream, server1_callback, stream);

  ssh_local_destroy_listener(listener1);  
  unlink(lpath1);
}

void connect1_write(SshStream stream)
{
  int len;
  while (ssh_buffer_len(&send_buffer) > 0)
    {
      len = ssh_buffer_len(&send_buffer);
      len = ssh_stream_write(stream, ssh_buffer_ptr(&send_buffer), len);
      if (len < 0)
	return;
      if (len == 0)
	ssh_fatal("connect1_write failed");
      ssh_buffer_consume(&send_buffer, len);
    }
  ssh_stream_output_eof(stream);
  ssh_stream_destroy(stream);
}

void connect1_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = context;
  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      break;
    case SSH_STREAM_CAN_OUTPUT:
      connect1_write(stream);
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("connect1_callback disconnected");
    }
}

void connect1_done(SshStream stream, void *context)
{
  unsigned char buf[100];

  if (context != (void *)3)
    ssh_fatal("connect1 bad context");
  if (!stream)
    ssh_fatal("connection failed");

  if (ssh_stream_read(stream, buf, sizeof(buf)) >= 0)
    ssh_fatal("connect1 read should have failed");
  
  ssh_stream_get_stats(stream, &stats);
  ssh_stream_set_callback(stream, connect1_callback, (void *)stream);
}

int main(int ac, char **av)
{
  int i, j;
  int pass;
  unsigned char buf[1024];

  snprintf(lpath1, sizeof (lpath1), "/tmp/lstr1.%x", (unsigned)random());
  snprintf(lpath2, sizeof (lpath2), "/tmp/lstr2.%x", (unsigned)random());
  
  printf("Doing %d iterations of localstream test:", PASSES);

  for (pass = 0; pass < PASSES; pass++)
    {
      printf(" %d", pass);
      fflush(stdout);

      ssh_buffer_init(&send_buffer);
      ssh_buffer_init(&expect_buffer);
      
      for (i = 0; i < 100; i++)
	{
	  for (j = 0; j < sizeof(buf); j++)
	    buf[j] = random();
	  ssh_buffer_append(&send_buffer, buf, sizeof(buf));
	  ssh_buffer_append(&expect_buffer, buf, sizeof(buf));
	  send_count += sizeof(buf);
	}

      ssh_event_loop_initialize();

      remove(lpath1);
      listener1 = ssh_local_make_listener(lpath1, 
					  listener1_callback,
					  (void *)4);
      if (!listener1) {
	  ssh_fatal("cannot create listener1");
      }

      ssh_local_connect(lpath1, connect1_done, (void *)3);

      ssh_event_loop_run();

      ssh_event_loop_uninitialize();

      ssh_buffer_uninit(&send_buffer);
      ssh_buffer_uninit(&expect_buffer);
      
    }
  printf("\n");
  
  return 0;
}
