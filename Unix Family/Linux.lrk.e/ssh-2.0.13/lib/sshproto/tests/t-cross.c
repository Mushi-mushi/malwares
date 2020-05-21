/*

t-cross.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

----- up tests:
  - tests basic functionality
----- down tests:
  - tests basic functionality
  - combined tests for up/down functionality
  - tests shortcircuiting

*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshcross.h"
#include "sshunixeloop.h"

/*

  - test Up/Down wrappers
     - passing full packets
     - passing partial packets
     - eof
     - destruction
     - can_send and exceeding it by 10000 bytes
     - can_receive and packet reception
     - shortcircuit

*/

SshBuffer *buffer;

void test_functions(int foo, ...)
{
  va_list va;

  unsigned char test1_str[9] = 
    {0x00, 0x00, 0x00, 0x05, 0x03, 0xDE, 0xAD, 0xBE, 0xEF};

  ssh_buffer_clear(buffer);
  if (ssh_cross_encode_packet(buffer, 3, SSH_FORMAT_UINT32,
                              (SshUInt32) 0xDEADBEEF,
                              SSH_FORMAT_END) != 9)
    ssh_fatal("test_functions: ssh_cross_encode_packet error");
  if (memcmp(ssh_buffer_ptr(buffer), test1_str, 9) != 0)
    ssh_fatal("test_functions: ssh_cross_encode_packet data error");

  ssh_buffer_clear(buffer);
  va_start(va, foo);
  if (ssh_cross_encode_packet_va(buffer, 3, va) != 9)
    ssh_fatal("test_functions: ssh_cross_encode_packet_va error");
  if (memcmp(ssh_buffer_ptr(buffer), test1_str, 9) != 0)
    ssh_fatal("test_functions: ssh_cross_encode_packet_va data error");
}

/* global variables for keeping track of these.. */

int up_received_packet_calls, up_received_eof_calls, 
  up_can_send_calls, up_destroy_calls;

int up_comparison_type;
SshBuffer *up_comparison_packet;

void up_received_packet(SshCrossPacketType type, const unsigned char *data,
                        size_t len, void *context)
{
  int i;

  up_received_packet_calls++;
  if (context != (void *)1)
    ssh_fatal("up_received_packet: context != 1");
  if (up_comparison_packet)
    if (ssh_buffer_len(up_comparison_packet) != len ||
        memcmp(ssh_buffer_ptr(up_comparison_packet), data, len) != 0)
      {
        ssh_debug("Expected:");
        buffer_dump(up_comparison_packet);
        ssh_debug("Got:");
        for (i = 0; i < len; i++)
          fprintf(stderr, "%02x ", data[i]);
        fprintf(stderr, "\n");

        ssh_fatal("up_received_packet: bad match with up_comparison_packet");
      }
}

void up_received_eof(void *context)
{
  up_received_eof_calls++;
  if (context != (void *)1)
    ssh_fatal("up_received_eof: context != 1");
}

void up_can_send(void *context)
{
  up_can_send_calls++;
  if (context != (void *)1)
    ssh_fatal("up_received_eof: context != 1");
}

void up_destroy(void *context)
{
  up_destroy_calls++;
  if (context != (void *)1)
    ssh_fatal("up_received_eof: context != 1");
}

void clear_up_calls()
{
  up_received_packet_calls = 0;
  up_received_eof_calls = 0;
  up_can_send_calls = 0;
  up_destroy_calls = 0;
}

SshStream up_create()
{
  SshStream up;

  clear_up_calls();
  up = ssh_cross_up_create(up_received_packet, up_received_eof, up_can_send,
                           up_destroy, (void *)1);
  return up;
}

int up_stream_input_calls, up_stream_output_calls;

void up_stream_callback(SshStreamNotification op, void *context)
{
  if (context != (void *)3)
    ssh_fatal("up_stream_callback: context != 3");
  switch (op)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      up_stream_input_calls++;
      break;
    case SSH_STREAM_CAN_OUTPUT:
      up_stream_output_calls++;
      break;
    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("up_stream_callback: DISCONNECTED");
    default:
      ssh_fatal("up_stream_callback: op %d", (int)op);
    }
}

void simple_up_tests()
{
  SshStream up;
  unsigned char buf[100];

  /* Simple destroy with all callbacks NULL. */
  up = ssh_cross_up_create(NULL, NULL, NULL, NULL, NULL);
  ssh_event_loop_run();
  if (ssh_stream_write(up, "\1", 1) >= 0)
    ssh_fatal("simple_up-tests: write NULL without can_receive fail");
  ssh_cross_up_can_receive(up, TRUE);
  if (ssh_stream_write(up, (const unsigned char *)"\1\0\0\0\2\3\4", 7) != 7)
    ssh_fatal("simple_up_tests: write NULL");
  ssh_event_loop_run();
  /* partial packet left in buffers... */
  if (ssh_stream_write(up, (const unsigned char *)"\1\0\0\0\2\3", 6) != 6)
    ssh_fatal("simple_up_tests: write NULL partial");
  ssh_event_loop_run();
  ssh_stream_output_eof(up);
  ssh_event_loop_run();
  ssh_stream_destroy(up);
  ssh_event_loop_run();
  
  /* Simple destroy with no intermediate ssh_event_loop_run. */
  up = up_create();
  ssh_stream_destroy(up);
  ssh_event_loop_run();
  if (up_received_packet_calls != 0 || up_received_eof_calls != 0 ||
      up_can_send_calls != 0 || up_destroy_calls != 1)
    ssh_fatal("simple_up_tests: simple destroy 1 fail 1");
  
  /* Simple destroy with intermediate ssh_event_loop_run. */
  up = up_create();
  ssh_event_loop_run();

  if (up_received_packet_calls != 0 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)
    ssh_fatal("simple_up_tests: simple destroy 2 fail 1 (1)");

  ssh_stream_destroy(up);
  ssh_event_loop_run();
  if (up_received_packet_calls != 0 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 1)
    ssh_fatal("simple_up_tests: simple destroy 2 fail 2 (2)");
  
  /* Simple destroy with intermediate ssh_event_loop_run, write, and EOF. */
  up = up_create();
  ssh_cross_up_can_receive(up, TRUE);
  ssh_event_loop_run();
  if (up_received_packet_calls != 0 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)
    ssh_fatal("simple_up_tests: simple destroy 2 fail 1 (3)");
  up_comparison_type = 2;

  if (ssh_stream_write(up, "\0\0\0\1\2", 5) != 5)
    ssh_fatal("simple_up_tests: simple write empty packet fail");

  if (up_received_packet_calls != 1 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)
    ssh_fatal("simple_up_tests: simple destroy 2 fail 1 (4)");

  up_comparison_type = 3;
  if (ssh_stream_write(up, "\0\0\0\2\3", 5) != 5)
    ssh_fatal("simple_up_tests: simple write partial packet fail");

  if (up_received_packet_calls != 1 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)

    ssh_fatal("simple_up_tests: simple write parital packet fail 2");
  if (ssh_stream_write(up, "\6", 1) != 1)
    ssh_fatal("simple_up_tests: simple write rest of partial fail");
  if (up_received_packet_calls != 2 || up_received_eof_calls != 0 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)
    ssh_fatal("simple_up_tests: simple write rest of partial fail 2");
  ssh_stream_output_eof(up);
  ssh_event_loop_run();
  if (up_received_packet_calls != 2 || up_received_eof_calls != 1 ||
      up_can_send_calls != 1 || up_destroy_calls != 0)
    ssh_fatal("simple_up_tests: simple eof fail");
  ssh_stream_destroy(up);
  ssh_event_loop_run();
  if (up_received_packet_calls != 2 || up_received_eof_calls != 1 ||
      up_can_send_calls != 1 || up_destroy_calls != 1)
    ssh_fatal("simple_up_tests: simple destroy 2 fail 2");

  /* Test up_send and up_send_eof. */
  up = up_create();
  ssh_stream_set_callback(up, up_stream_callback, (void *)3);
  ssh_event_loop_run();
  up_stream_input_calls = 0;
  if (ssh_cross_up_can_send(up) != TRUE)
    ssh_fatal("simple_up_tests: cannot send");
  if (ssh_stream_read(up, buf, sizeof(buf)) != -1)
    ssh_fatal("simple_up_tests: read != 0");
  ssh_cross_up_send(up, 7, "\2\3", 2);
  ssh_cross_up_send_eof(up);
  ssh_event_loop_run();
  if (up_stream_input_calls == 0)
    ssh_fatal("up_stream_input_calls: stream callback not called");

  if (ssh_stream_read(up, buf, sizeof(buf)) != 7)
    ssh_fatal("simple_up_test: read error");
  if (memcmp(buf, "\0\0\0\3\7\2\3", 7) != 0)
    ssh_fatal("simple_up_test: read data error");

  if (ssh_stream_read(up, buf, sizeof(buf)) != 0)
    ssh_fatal("simple_up_test: read eof error");
  ssh_stream_destroy(up);

  ssh_event_loop_run();
}

int down_received_packet_calls, down_received_eof_calls, down_can_send_calls;

int down_comparison_type;
SshBuffer *down_comparison_packet;

void down_received_packet(SshCrossPacketType type, const unsigned char *data,
                        size_t len, void *context)
{
  down_received_packet_calls++;
  if (context != (void *)2)
    ssh_fatal("down_received_packet: context != 1");
  if (down_comparison_packet)
    if (ssh_buffer_len(down_comparison_packet) != len ||
        memcmp(ssh_buffer_ptr(down_comparison_packet), data, len) != 0)
      ssh_fatal("down_received_packet: bad match with down_comparison_packet");
}

void down_received_eof(void *context)
{
  down_received_eof_calls++;
  if (context != (void *)2)
    ssh_fatal("down_received_eof: context != 1");
}

void down_can_send(void *context)
{
  down_can_send_calls++;
  if (context != (void *)2)
    ssh_fatal("down_received_eof: context != 1");
}

void clear_down_calls()
{
  down_received_packet_calls = 0;
  down_received_eof_calls = 0;
  down_can_send_calls = 0;
}

SshCrossDown down_create(SshStream stream)
{
  SshCrossDown down;

  clear_down_calls();
  down = ssh_cross_down_create(stream, down_received_packet, down_received_eof,
                               down_can_send, (void *)2);
  return down;
}

void simple_down_tests()
{
  SshCrossDown down;
  SshStream stream;

  stream = up_create();
  down = ssh_cross_down_create(stream, NULL, NULL, NULL, NULL);
  ssh_cross_down_can_receive(down, TRUE);
  ssh_event_loop_run();
  ssh_cross_up_send_debug(stream, TRUE, "aaaaa");
  ssh_cross_up_send_eof(stream);
  ssh_event_loop_run();
  ssh_cross_down_send_eof(down);
  ssh_cross_down_destroy(down);
  ssh_event_loop_run();

  if (up_received_eof_calls != 1 || up_destroy_calls != 1)
    ssh_fatal("simple_down_tests NULL up eof/destroy not received");
  stream = up_create();
  ssh_cross_up_can_receive(stream, TRUE);
  down = down_create(stream);
  up_comparison_type = 5;
  up_comparison_packet = ssh_buffer_allocate();
  ssh_buffer_append(up_comparison_packet, "\1\2\3", 3);
  if (ssh_cross_down_can_send(down) != TRUE)
    ssh_fatal("simple_down_tests: cannot send");
  ssh_cross_down_send(down, 5, "\1\2\3", 3);
  ssh_event_loop_run();
  ssh_buffer_free(up_comparison_packet);
  up_comparison_packet = NULL;
  if (up_received_packet_calls != 1)
    ssh_fatal("simple_down_tests: up packet not received");

  up_comparison_type = SSH_CROSS_DISCONNECT;
  ssh_cross_down_send_disconnect(down, TRUE, 1, "foo");
  ssh_event_loop_run();
  if (up_received_packet_calls != 2)
    ssh_fatal("simple_down_tests: down_disconnect not received");

  up_comparison_type = SSH_CROSS_DEBUG;
  ssh_cross_down_send_debug(down, TRUE, "bar");
  ssh_event_loop_run();
  if (up_received_packet_calls != 3)
    ssh_fatal("simple_down_tests: down_debug not received");

  ssh_cross_up_can_receive(stream, FALSE);
  ssh_cross_down_send_debug(down, FALSE, "baz");
  ssh_event_loop_run();
  if (up_received_packet_calls != 3)
    ssh_fatal("simple_down_tests: up_can_receive FALSE failed");
  ssh_cross_up_can_receive(stream, TRUE);
  ssh_event_loop_run();
  if (up_received_packet_calls != 4)
    ssh_fatal("simple_down_tests: up_can_receive TRUE failed");
  
  up_comparison_type = 12345678;
  ssh_cross_down_send_encode(down, 12345678, SSH_FORMAT_END);
  ssh_event_loop_run();
  if (up_received_packet_calls != 5)
    ssh_fatal("simple_down_tests: down_send_encode not received");

  down_comparison_type = SSH_CROSS_DISCONNECT;
  ssh_cross_up_send_disconnect(stream, FALSE, 12121, "zz");
  ssh_event_loop_run();
  if (down_received_packet_calls != 0)
    ssh_fatal("simple_down_tests: up_send_disconnect received wo can_receive");
  ssh_cross_down_can_receive(down, TRUE);
  ssh_event_loop_run();
  if (down_received_packet_calls != 1)
    ssh_fatal("simple_down_tests: up_send_disconnect not received");

  down_comparison_type = SSH_CROSS_DEBUG;
  ssh_cross_up_send_debug(stream, FALSE, "y");
  ssh_event_loop_run();
  if (down_received_packet_calls != 2)
    ssh_fatal("ssh_down_tests: up_send_debug not received");

  down_comparison_type = 9876;
  ssh_cross_up_send_encode(stream, 9876, SSH_FORMAT_DATA, "a", 1,
                           SSH_FORMAT_END);
  ssh_event_loop_run();
  if (down_received_packet_calls != 3)
    ssh_fatal("ssh_down_tests: up_send_encode not received");

  ssh_cross_up_send_eof(stream);
  ssh_event_loop_run();
  if (down_received_eof_calls != 1)
    ssh_fatal("ssh_down_tests: up_send_eof not received");
  
  ssh_cross_down_send_eof(down);
  ssh_cross_down_destroy(down);
  ssh_event_loop_run();
  if (up_destroy_calls != 1)
    ssh_fatal("simple_down_tests: destroy did not close stream");
  if (up_received_eof_calls != 1)
    ssh_fatal("simple_down_tests: up eof not called");
}


SshStream sc_up;
SshCrossDown sc_down;
Boolean sc_active;

void sc_received_packet(SshCrossPacketType type, const unsigned char *data,
                        size_t len, void *context)
{
  if (type == 1)
    return;
  if (type == 0xcc)       /* Shortcircuit magic cookie */
    {
      ssh_cross_shortcircuit(sc_up, sc_down);
      sc_active = TRUE;
      return;
    }
  ssh_fatal("sc_received_packet: bad packet");
}

void shortcircuit_tests()
{
  SshCrossDown test_down, above;
  SshStream under, test_up;

  sc_active = FALSE;
  under = up_create();
  test_down = ssh_cross_down_create(under, sc_received_packet, NULL,
                                    NULL, NULL);
  test_up = ssh_cross_up_create(NULL, NULL, NULL, NULL, NULL);
  above = down_create(test_up);

  ssh_cross_up_can_receive(under, TRUE);
  ssh_cross_down_can_receive(test_down, TRUE);
  ssh_cross_up_can_receive(test_up, TRUE);
  ssh_cross_down_can_receive(above, TRUE);

  ssh_event_loop_run();

  sc_up = test_up;
  sc_down = test_down;
  /* Trigger shortcircuiting with a magic packet. */
  ssh_cross_down_can_receive(test_down, FALSE);
  ssh_cross_up_send(under, 1, NULL, 0);
  ssh_cross_up_send(under, 0xcc, NULL, 0);
  down_comparison_type = 7;
  down_comparison_packet = ssh_buffer_allocate();
  ssh_buffer_append(down_comparison_packet, "ABC", 3);
  ssh_cross_up_send(under, 7, "ABC", 3);
  ssh_event_loop_run();
  if (down_received_packet_calls != 0)
    ssh_fatal("shortcircuit_tests: Received packets too soon");
  ssh_cross_down_can_receive(test_down, TRUE);
  ssh_event_loop_run();
  if (down_received_packet_calls != 1)
    ssh_fatal("shortcircuit_tests: didn't receive packets");
  ssh_buffer_clear(down_comparison_packet);
  ssh_buffer_append(down_comparison_packet, "DEF", 3);
  down_comparison_type = 8;
  ssh_cross_up_send(under, 8, "DEF", 3);
  ssh_event_loop_run();
  if (down_received_packet_calls != 2)
    ssh_fatal("shortcircuit_tests: didn't properly receive packet");
  ssh_buffer_free(down_comparison_packet);
  down_comparison_packet = NULL;
  if (up_destroy_calls != 0)
    ssh_fatal("shortcircuit_tests: up destroy count != 0");
  ssh_cross_down_destroy(above);
  ssh_cross_down_destroy(test_down);
  if (up_destroy_calls == 0)
    ssh_fatal("shortcircuit_tests: up didn't get destroyed");
}

int main()
{
  int pass;

  for (pass = 0; pass < 1000; pass++)
    {
      buffer = ssh_buffer_allocate();
      test_functions(0, SSH_FORMAT_UINT32, (SshUInt32) 0xDEADBEEF,
                     SSH_FORMAT_END);
      ssh_buffer_free(buffer);
    }

  for (pass = 0; pass < 1000; pass++)
    {
      ssh_event_loop_initialize();

      simple_up_tests();
      simple_down_tests();
      shortcircuit_tests();

      ssh_event_loop_uninitialize();
    }
  
  return 0;
}
