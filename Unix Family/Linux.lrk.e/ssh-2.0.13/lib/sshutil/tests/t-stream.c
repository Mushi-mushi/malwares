/*

t-stream.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 23:10:57 1996 ylo

*/

/*
 * $Id: t-stream.c,v 1.14 1998/07/30 18:43:48 kivinen Exp $
 * $Log: t-stream.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "sshunixeloop.h"

#undef NO_NAME_SERVICE

#define OUTSIDE_TESTS

#ifdef WINDOWS
#define random()  rand()
#endif /* WINDOWS */
#define PASSES 200
#define SOCKSHOST "socks://kivinen@muuri.ssh.fi:1080/"
#define SOCKSIP "192.168.2.254"
#define SOCKSLOCAL "socks://kivinen@muuri.ssh.fi:1080/127.0.0.0/8,192.168.2.0/24"
#define OUTSIDESSHHOST "chili.dipoli.hut.fi"
#define OUTSIDESSHIP "130.233.208.130"

#ifdef NO_NAME_SERVICE
# define LOCALHOST "127.0.0.1"
#else
# define LOCALHOST "localhost"
#endif

int exited1 = 0, exited2 = 0;
SshTcpListener listener1, listener2;
SshStream connect2;
SshStreamStats stats;
SshBuffer send_buffer, expect_buffer;
unsigned long send_count = 0, read_count = 0;

void connect2_done(SshIpError error, SshStream stream, void *context)
{
  ssh_stream_destroy(stream);
}

void timeout(void *context)
{
  if (context != (void *)1)
    abort();
  
  ssh_tcp_connect_with_socks(LOCALHOST, "34513", "", 2,
			     connect2_done, (void *)2);
}

void listener2_callback(SshIpError status, SshStream stream, void *context)
{
  char buf[100];

  if (status != SSH_IP_NEW_CONNECTION)
    ssh_fatal("listener2 status %d", status);

  if (!ssh_tcp_get_remote_address(stream, buf, sizeof(buf)) ||
      strcmp(buf, "127.0.0.1") != 0)
    ssh_fatal("listener2 remote address");

  memset(buf, 0, sizeof(buf));
  if (!ssh_tcp_get_local_address(stream, buf, sizeof(buf)) ||
      strcmp(buf, "127.0.0.1") != 0)
    ssh_fatal("listener2 remote address");

  ssh_stream_destroy(stream);
  exited2 = 1;

  ssh_tcp_destroy_listener(listener2);
}

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

void listener1_callback(SshIpError status, SshStream stream, void *context)
{
  if (status != SSH_IP_NEW_CONNECTION)
    ssh_fatal("listener1 status %d", status);

  ssh_stream_set_callback(stream, server1_callback, stream);

  ssh_tcp_destroy_listener(listener1);
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

void connect1_done(SshIpError status, SshStream stream, void *context)
{
  char buf[100];

  if (context != (void *)3)
    ssh_fatal("connect1 bad context");

  if (status != SSH_IP_OK)
    ssh_fatal("connect1 bad status %d", status);
  
  if (!ssh_tcp_get_local_port(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 local port");

  if (atoi(buf) < 1024 || atoi(buf) > 65535)
    ssh_fatal("connect1 local port value %d", buf);

  if (!ssh_tcp_get_remote_port(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 remote port");

  if (strcmp(buf, "34512") != 0)
    ssh_fatal("connect1 remote port value %d", buf);

  if (!ssh_tcp_get_local_address(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 local address");

  if (!ssh_tcp_get_remote_address(stream, buf, sizeof(buf)))
    ssh_fatal("connect1 remote address");

  if (ssh_tcp_has_ip_options(stream))
    ssh_fatal("connect1 ip options");

  if (ssh_stream_read(stream, (unsigned char *) buf, sizeof(buf)) >= 0)
    ssh_fatal("connect1 read should have failed");
  
  ssh_stream_get_stats(stream, &stats);
  ssh_stream_set_callback(stream, connect1_callback, (void *)stream);
}

void listenerfail_callback(SshIpError status, SshStream stream, void *context)
{
  ssh_fatal("listenerfail_callback called");
}

void connectfail_done(SshIpError status, SshStream stream, void *context)
{
  if (status == SSH_IP_OK)
    ssh_fatal("Connectfail_done: succeeded when should have failed");
}

void connectssh_callback(SshStreamNotification notification, void *context)
{
  SshStream stream = (SshStream)context;
  unsigned char buf[1];
  int len;
  
  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      while ((len = ssh_stream_read(stream, buf, 1)) > 0)
	{
	  if (buf[0] == '\n')
	    break;
	}
      if (len == 0 ||
	  (len == 1 && buf[0] == '\n'))
	{
	  ssh_stream_destroy(stream);
	  return;
	}
      break;
    case SSH_STREAM_CAN_OUTPUT:
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("connectssh_callback: received DISCONNECTED");
    default:
      ssh_fatal("connectssh_callback: unexpected notification %d", notification);
    }
}

void connectssh_done(SshIpError status, SshStream stream, void *context)
{
  if (status != SSH_IP_OK)
    ssh_fatal("connectssh_done: connecting to %s ssh failed",
	      OUTSIDESSHHOST);
  ssh_stream_set_callback(stream, connectssh_callback, (void *)stream);
}

char *ok_netmask_tests[][2] = {
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.4" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.22" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.0" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.4.255" },
  { "1.2.3.4", "1.2.3.4" },
  { "1.2.3.4/8", "1.2.3.4" }, 
  { "1.2.3.4/8", "1.3.4.5" },
  { "1.2.3.4/16", "1.2.4.5" },
  { "1.2.3.4/16", "1.2.44.22" }, 
  { "1.2.3.4/24", "1.2.3.4" },
  { "1.2.3.4/24", "1.2.3.255" },
  { "1.2.3.4/28", "1.2.3.6" },
  { "1.2.3.4/28", "1.2.3.15" }
};

char *fail_netmask_tests[][2] = {
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.5" },
  { "1.2.3.4/32,2.3.4.0/24", "1.2.3.22" },
  { "1.2.3.4/32,2.3.4.0/24", "2.3.5.22" },
  { "1.2.3.4", "2.3.4.255" },
  { "1.2.3.4", "1.2.3.5" },
  { "1.2.3.4/8", "2.3.4.5" },
  { "1.2.3.4/16", "2.2.44.22" },
  { "1.2.3.4/24", "1.2.4.22" },
  { "1.2.3.4/24", "1.3.3.22" },
  { "1.2.3.4/24", "2.2.3.22" },
  { "1.2.3.4/28", "1.2.3.16" },
  { "1.2.3.4/28", "1.2.3.64" },
  { "1.2.3.4/28", "1.2.3.128" },
  { "1.2.3.4/28", "1.2.3.255" }
};

int main(int ac, char **av)
{
  int i, j;
  int pass;
  unsigned char buf[1024];
  int exitval = 0;
  
  printf("Doing %d iterations of stream test:", PASSES);
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
      
      if (ssh_tcp_get_port_by_service("telnet", "tcp") != 23)
	{
	  printf("get_port_by_service failed\n");
	  exitval = 1;
	}
      ssh_tcp_get_service_by_port(23, "tcp", (char *) buf, sizeof(buf));
      if (strcmp((char *) buf, "telnet") != 0)
	{
	  fprintf(stderr, "get_service_by_port failed\n");
	  exitval = 1;
	}
      if (!ssh_inet_is_valid_ip_address("255.2.0.40") ||
	  ssh_inet_is_valid_ip_address("1.2.304.4") ||
	  ssh_inet_is_valid_ip_address("5.4.3.2.1"))
	{
	  fprintf(stderr, "is_valid_ip_address failed\n");
	  exitval = 1;
	}
      if (ssh_inet_ip_address_compare("1.2.3.4", "001.002.003.04") != 0 ||
	  ssh_inet_ip_address_compare("1.2.3.4", "4.3.2.1") == 0)
	{
	  fprintf(stderr, "ip_address_compare failed\n");
	  exitval = 1;
	}
      for(i = 0; i < sizeof(ok_netmask_tests) / sizeof(*ok_netmask_tests); i++)
	{
	  if (!ssh_inet_compare_netmask(ok_netmask_tests[i][0],
					ok_netmask_tests[i][1]))
	      {
		fprintf(stderr, "ssh_inet_compare_netmask failed, "
			"netmask = %s, ip = %s\n",
			ok_netmask_tests[i][0], ok_netmask_tests[i][1]);
		exitval = 1;
	      }
	  if (ssh_inet_compare_netmask(fail_netmask_tests[i][0],
				       fail_netmask_tests[i][1]))
	      {
		fprintf(stderr, "ssh_inet_compare_netmask succeded "
			"(should fail), netmask = %s, ip = %s\n",
			fail_netmask_tests[i][0], fail_netmask_tests[i][1]);
		exitval = 1;
	      }
	}
      ssh_event_loop_initialize();

      /* Try creating a failing listener. */
      listener1 = ssh_tcp_make_listener("0.0.0.0", "34512",
					   listenerfail_callback, NULL);
      if (!listener1)
	ssh_fatal("Creating listener1 failed");
      listener2 = ssh_tcp_make_listener("0.0.0.0", "34512",
					   listenerfail_callback, NULL);
      if (listener2)
	ssh_fatal("Creating listener2 succeeded when it should fail.");
      ssh_tcp_destroy_listener(listener1);

      /* Try making a failing connection. */
      ssh_tcp_connect_with_socks("127.1", "34512", NULL, 2,
				 connectfail_done, NULL);
      /* For the first half, do the tests one at a time to ease debugging. */
#ifndef WINDOWS /* In Windows we must run the event loop all the time */
      if (pass < PASSES / 2)
#endif
	ssh_event_loop_run();
      
#ifdef OUTSIDE_TESTS
      /* XXX this currently kills both muuri and shadows when repeated... */
      /* Try connecting with socks to a successful address. */

      if (pass % 50 == 0)
	{
	  /* Try connecting with socks to a failing address. */
	  ssh_tcp_connect_with_socks(OUTSIDESSHHOST, "34512", SOCKSHOST,
				     2, connectfail_done, NULL);
	  /* First time, do the tests one at a time to ease debugging. */
	  if (pass < PASSES / 2)
	    ssh_event_loop_run();
	  
	  /* Try connecting with socks to a failing address. */
	  ssh_tcp_connect_with_socks(OUTSIDESSHHOST, "34512", SOCKSIP,
				     2, connectfail_done, NULL);
	  /* First time, do the tests one at a time to ease debugging. */
	  if (pass < PASSES / 2)
	    ssh_event_loop_run();
	  
	  /* Try connecting with socks to a successful address. */
	  ssh_tcp_connect_with_socks(OUTSIDESSHIP, "22", SOCKSHOST,
				     2, connectssh_done, NULL);
	  /* First time, do the tests one at a time to ease debugging. */
	  if (pass < PASSES / 2)
	    ssh_event_loop_run();

	  /* Try connecting with socks to a successful address. */
	  ssh_tcp_connect_with_socks(OUTSIDESSHIP, "22", SOCKSIP,
				     2, connectssh_done, NULL);
	  /* First time, do the tests one at a time to ease debugging. */
	  if (pass < PASSES / 2)
	    ssh_event_loop_run();
	}
#endif /* OUTSIDE_TESTS */

      /* Create two listeners, make a connection, and pass some data.
         This tests
	   - that the callbacks get called when set
	   - that data can be transmitted
	   - that EOF is passed ok */
      listener1 = ssh_tcp_make_listener("0.0.0.0", "34512",
					listener1_callback, NULL);
      listener2 = ssh_tcp_make_listener("127.0.0.1", "34513",
					listener2_callback, NULL);
      ssh_register_timeout(0L, 50000L, timeout, (void *)1);
      
#ifdef NO_NAME_SERVICE
      ssh_tcp_get_host_name((char *) buf, sizeof(buf));
#else
      strncpy((char *) buf, LOCALHOST, sizeof (buf));
      buf[sizeof (buf) - 1] = '\0';
#endif
      
      ssh_tcp_connect_with_socks((char *) buf, "34512", SOCKSLOCAL, 2,
				 connect1_done, (void *)3);

      /* This is supposed to exit when all the listeners and connecting streams
	 have destroyed themselves. */
      ssh_event_loop_run();

      if (!exited1 || !exited2)
	ssh_fatal("exited1=%d exited2=%d", exited1, exited2);
      
      ssh_event_loop_uninitialize();
      ssh_buffer_uninit(&send_buffer);
      ssh_buffer_uninit(&expect_buffer);
    }
  printf("\n");
  
  return exitval;
}
