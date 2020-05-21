/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Sep 15 18:49:44 1997 [ttsalo]

  Udp socket wrapper tests

  */

/*
 * $Id: t-udp.c,v 1.6 1998/10/08 15:43:41 kivinen Exp $
 * $Log: t-udp.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshudp.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

SshUdpListener c_listener, p_listener;
unsigned char c_data[256];
unsigned char p_data[] = "DEADBEEF foobaz";
unsigned char p2_data[256];

void p_timeout_callback(void *context)
{
  ssh_udp_send(p_listener, "127.0.0.1", "54678",
               p_data, strlen((char *) p_data));
}

void p_callback(SshUdpListener listener, void *context)
{
  size_t received;
  char remote_address[256];
  char remote_port[16];
  SshUdpError error;

  error = ssh_udp_read(listener, remote_address, 256,
                       remote_port, 16,
                       p2_data, 256, &received);
  ssh_udp_destroy_listener(listener);

  if (memcmp(p_data, p2_data, strlen((char *) p_data)))
    {
      printf("Test failed (failure to communicate)\n");
      exit(1);
    }
}

void c_callback(SshUdpListener listener, void *context)
{
  char remote_address[256];
  char remote_port[16];
  size_t received;
  SshUdpError error;
  
  error = ssh_udp_read(listener, remote_address, 256,
                       remote_port, 16,
                       c_data, 256, &received);
  ssh_udp_send(listener, "127.0.0.1", "54321",
               c_data, strlen((char *) c_data));
  ssh_udp_destroy_listener(listener);
}

void c(void)
{
  ssh_event_loop_initialize();
  c_listener = ssh_udp_make_listener("127.0.0.1", "54678", NULL, NULL,
                                     c_callback, NULL);
  if (c_listener == NULL)
    {
      printf("Listener creation failed.\n");
      exit(1);
    }
  
  ssh_event_loop_run();
  ssh_debug("child exiting...");
}

void p(void)
{
  ssh_event_loop_initialize();
  
  p_listener = ssh_udp_make_listener(NULL, "54321", NULL, NULL,
                                     p_callback, NULL);
  
  if (p_listener == NULL)
    {
      printf("Listener creation failed.\n");
      exit(1);
    }
  ssh_register_timeout(2, 0, p_timeout_callback, NULL);
  ssh_event_loop_run();
  ssh_debug("parent exiting...");
}

void usage(void)
{
  fprintf(stderr, "Usage: t-udp [-c|-p]\n");
}

int main(int argc, char **argv)
{
  pid_t pid;
  
  memset(c_data, 0, 256);
  memset(p2_data, 0, 256);

  /* In the actual test, the parent will send bytes to the
     child, child will mirror them back and parent will check
     that it got the same bytes back. */

  if (argc == 2)
    {
      if (argv[1][0] == '-' && argv[1][1] == 'c')
        {
          c();
          exit(0);
        }
      else if (argv[1][0] == '-' && argv[1][1] == 'p')
        {
          p();
          exit(0);
        }
      else
        {
          usage();
          exit(1);
        }
    }
  if (argc != 1)
    {
      usage();
      exit(1);
    }

  pid = fork();
  if (pid == 0)
    {
      c();
      exit(0);
    }
  else
    {
      int status;
      
      p();
      if (wait(&status) != pid)
        {
          ssh_fatal("Wrong pid returned by wait");
        }
      if (WIFSIGNALED(status))
        {
          ssh_fatal("Child exited with signal %d", WTERMSIG(status));
        }
      if (WEXITSTATUS(status) != 0)
        {
          ssh_fatal("Child exited with status %d", WEXITSTATUS(status));
        }
    }

  exit(0);
}
