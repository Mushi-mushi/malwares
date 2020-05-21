/*
 * t-serial.c -- Serial stream test program
 *
 * Copyright (c) 1998 Tero Kivinen <kivinen@iki.fi>
 */
/*
 *        Program: t-serial
 *        $Source: /ssh/CVS/src/lib/sshutil/tests/t-serial.c,v $
 *        Author : $Author: kivinen $
 *
 *        Creation          : 13:40 Aug 17 1998 kivinen
 *        Last Modification : 20:42 Jan 19 1999 kivinen
 *        Last check in     : $Date: 1999/01/19 18:43:27 $
 *        Revision number   : $Revision: 1.7 $
 *        State             : $State: Exp $
 *        Version           : 1.316
 *
 *        Description       : Serial stream test program
 *
 *        Requirements      : A supported smart card reader
 *                            attached to a serial port.
 *                            Access rights to the serial port.
 *
 *        $Log: t-serial.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshserialstream.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"

#ifdef WINDOWS
#include "sshwineloop.h"
#else /* WINDOWS */
#include "sshunixeloop.h"
#endif /* WINDOWS */

#define SSH_DEBUG_MODULE "Main"

#define SSH_SC_READ_BUFFER_LEN          1024

typedef enum {
  SMART_CARD_IDLE,
  SMART_CARD_ATR_RECEIVED,
  SMART_CARD_DONE,
  SMART_CARD_TOWITOKO_ACTIVATE,
  SMART_CARD_TOWITOKO_ATR_L,
  SMART_CARD_TOWITOKO_ATR_H
} SmartCardState;

typedef enum {
  SMART_CARD_READER_UNKNOWN,
  SMART_CARD_READER_SETEC,
  SMART_CARD_READER_TOWITOKO
} SmartCardReaderType;

typedef struct SmartCardRec {
  char *name;
  SshStream stream;

  SshBuffer *buffer_in;
  SshBuffer *buffer_out;

  SmartCardState state;
  SmartCardReaderType type;
  SshSerialModemControl modem;
} *SmartCard;

void sc_process_input(SmartCard sc);
void sc_stream_callback(SshStreamNotification notification,
                        void *context);

SmartCard sc_open(char *tty_name, char *name)
{
  SmartCard sc;
  
  sc = ssh_xcalloc(1, sizeof(*sc));
  
  sc->name = name;
  sc->stream = ssh_serial_open(tty_name);

  if (sc->stream == NULL)
    ssh_fatal("ssh_serial_open failed");

  if (!ssh_serial_stream_params(sc->stream,
                                SSH_SERIAL_SPEED_9600, SSH_SERIAL_SPEED_9600,
                                SSH_SERIAL_BITS_8, SSH_SERIAL_PARITY_EVEN,
                                SSH_SERIAL_STOP_BITS_2,
                                SSH_SERIAL_MODE_RAW_LOCAL,
                                SSH_SERIAL_FLOW_NONE))
    ssh_fatal("ssh_serial_stream_params failed");

  if (!ssh_serial_stream_modem_set(sc->stream, SSH_SERIAL_MODEM_DTR))
    ssh_fatal("ssh_serial_stream_modem_set for %s failed", sc->name);
  
  if (!ssh_serial_stream_modem_get(sc->stream, &sc->modem))
    ssh_fatal("ssh_serial_stream_modem_get failed");

  ssh_stream_set_callback(sc->stream, sc_stream_callback, sc);
  sc->buffer_in = ssh_buffer_allocate();
  sc->buffer_out = ssh_buffer_allocate();
  sc->state = SMART_CARD_IDLE;
  sc->type = SMART_CARD_READER_UNKNOWN;
  return sc;
}

void sc_close(void *ctx)
{
  SmartCard sc = ctx;

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sc);
  ssh_stream_destroy(sc->stream);
  ssh_buffer_free(sc->buffer_in);
  ssh_buffer_free(sc->buffer_out);
  ssh_xfree(sc);
}

void sc_print_buffer(char *name, char *str,
                     unsigned char *buffer, size_t buflen)
{
  size_t i, j;
  
  for(i = 0; i < buflen; i += 16)
    {
      printf("%s %s %08x: ", name, str, i);
      for(j = 0; j < 16; j++)
        {
          if (i + j < buflen)
            printf("%02x", buffer[i + j]);
          else
            printf("  ");
          if ((j % 2) == 1)
            printf(" ");
        }
      printf("  ");
      for(j = 0; j < 16; j++)
        {
          if (i + j < buflen)
            if (isprint(buffer[i + j]))
              printf("%c", buffer[i + j]);
            else
              printf(".");
          else
            printf(" ");
        }
      printf("\n");
    }
}

/* Serial stream notification callback */
void sc_stream_callback(SshStreamNotification notification,
                        void *context)
{
  SmartCard sc = (SmartCard) context;
  unsigned char *p;
  int l;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      SSH_DEBUG(8, ("Input available from %s", sc->name));
      while (1)
        {
          ssh_buffer_append_space(sc->buffer_in, &p,
                                  SSH_SC_READ_BUFFER_LEN);
          l = ssh_stream_read(sc->stream, p, SSH_SC_READ_BUFFER_LEN);
          
          if (l < 0)
            {
              SSH_DEBUG(9, ("Read blocked from %s", sc->name));
              ssh_buffer_consume_end(sc->buffer_in, SSH_SC_READ_BUFFER_LEN);
              return;
            }

          if (l == 0)
            ssh_fatal("Eof received");

          ssh_buffer_consume_end(sc->buffer_in, SSH_SC_READ_BUFFER_LEN - l);
          sc_print_buffer(sc->name, "<-", ssh_buffer_ptr(sc->buffer_in) +
                          ssh_buffer_len(sc->buffer_in) - l, l);
          SSH_DEBUG(8, ("Read %ld bytes, total size of input buffer %ld from %s",
                        l, ssh_buffer_len(sc->buffer_in), sc->name));
          sc_process_input(sc);
        }
      break;

    case SSH_STREAM_CAN_OUTPUT:
      if (ssh_buffer_len(sc->buffer_out) == 0)
        {
          SSH_DEBUG(7, ("Can output, but nothing to send to %s", sc->name));
          return;
        }

      while (ssh_buffer_len(sc->buffer_out) != 0)
        {
          SSH_DEBUG(7, ("Can output, sending %ld bytes to %s",
                        ssh_buffer_len(sc->buffer_out), sc->name));
          l = ssh_stream_write(sc->stream,
                               ssh_buffer_ptr(sc->buffer_out),
                               ssh_buffer_len(sc->buffer_out));
          if (l == 0)
            ssh_fatal("Broken pipe");
          if (l < 0)
            {
              SSH_DEBUG(8, ("Write blocked to %s", sc->name));
              return;
            }
          sc_print_buffer(sc->name, "->", ssh_buffer_ptr(sc->buffer_out), l);
          ssh_buffer_consume(sc->buffer_out, l);
        }
      SSH_DEBUG(8, ("All written to %s", sc->name));
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_fatal("Disconnected");
      break;
    }
}

unsigned char sc_calc_towitoko_checksum(unsigned char start,
                                        unsigned char *buffer,
                                        size_t len)
{
  unsigned char checksum;
  int i;
  
  checksum = start;
  for(i = 0; i < len; i++)
    {
      checksum ^= buffer[i];
      checksum = ((checksum << 1) & 0xfe) | (((checksum >> 7) & 0x01) ^ 0x01);
    }
  return checksum;
}

void append_str(SmartCard sc, unsigned char *buffer, size_t len)
{
  ssh_buffer_append(sc->buffer_out, buffer, len);
  if (sc->type == SMART_CARD_READER_TOWITOKO)
    {
      unsigned char checksum;
      checksum = sc_calc_towitoko_checksum(0x00, buffer, len);
      ssh_buffer_append(sc->buffer_out, &checksum, 1);
    }
}

void append_command(SmartCard sc, unsigned char class,
                    unsigned char inst,
                    unsigned char p1,
                    unsigned char p2,
                    unsigned char length,
                    unsigned char *data,
                    size_t data_len)
{
  unsigned char buffer[4];

  if (sc->type == SMART_CARD_READER_TOWITOKO)
    {
      snprintf((char *) buffer, sizeof(buffer), "\x6f%c\x05", 5 + data_len);
      append_str(sc, buffer, 3);
    }
  ssh_buffer_append(sc->buffer_out, &class, 1);
  ssh_buffer_append(sc->buffer_out, &inst, 1);
  ssh_buffer_append(sc->buffer_out, &p1, 1);
  ssh_buffer_append(sc->buffer_out, &p2, 1);
  ssh_buffer_append(sc->buffer_out, &length, 1);
  ssh_buffer_append(sc->buffer_out, data, data_len);
}

void sc_process_setec(SmartCard sc)
{
  unsigned char *p;
  size_t l;

  p = ssh_buffer_ptr(sc->buffer_in);
  l = ssh_buffer_len(sc->buffer_in);

  switch (sc->state)
    {
    case SMART_CARD_IDLE:
      if (*p != 0x3b)
        {
          SSH_DEBUG(4, ("Setec: No sync char found from %s", sc->name));
          ssh_buffer_clear(sc->buffer_in);
        }
      else
        {
          int len;
          
          len = (p[1] & 0x0f) + 2;
          if (p[1] & 0x10) len++;
          if (p[1] & 0x20) len++;
          if (p[1] & 0x40) len++;
          if (p[1] & 0x80) len++;
          if (l < len) return;
          SSH_DEBUG(6, ("Setec: Got attr from %s", sc->name));
          ssh_buffer_consume(sc->buffer_in, len);
          sc->state = SMART_CARD_ATR_RECEIVED;
          append_command(sc, 0xa0, 0xf2, 0x00, 0x00, 22, NULL, 0);
          sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
        }
      break;
    case SMART_CARD_ATR_RECEIVED:
      if (l < 1 + 22 + 2)
        return;
      if (*p != 0xf2)
        {
          SSH_DEBUG(4, ("Setec: Invalid response to status from %s",
                        sc->name));
          ssh_buffer_clear(sc->buffer_in);
          return;
        }
      SSH_DEBUG(6, ("Setec: Got Status from %s", sc->name));
      ssh_buffer_consume(sc->buffer_in, 22);
      sc->state = SMART_CARD_DONE;
      break;
    default:
      break;
    }
}

void sc_send_check(void *ctx)
{
  SmartCard sc = ctx;

  SSH_DEBUG(5, ("Sending check to %s", sc->name));
  append_str(sc, (unsigned char *) "\x03", 1);
  sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
  ssh_register_timeout(2, 0, sc_send_check, sc);
}

void sc_send_atr(void *ctx)
{
  SmartCard sc = ctx;

  if (sc->state == SMART_CARD_TOWITOKO_ATR_H)
    {
      append_str(sc, (unsigned char *) "\xa0\x6f\x00\x05", 4);
      sc->state = SMART_CARD_TOWITOKO_ATR_L;
    }
  else
    {
      append_str(sc, (unsigned char *) "\x80\x6f\x00\x05", 4);
      sc->state = SMART_CARD_TOWITOKO_ATR_H;
    }
  sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
  ssh_register_timeout(2, 0, sc_send_atr, sc);
}

void sc_process_towitoko(SmartCard sc)
{
  unsigned char *p;
  size_t l;

  p = ssh_buffer_ptr(sc->buffer_in);
  l = ssh_buffer_len(sc->buffer_in);

  switch (sc->state)
    {
    case SMART_CARD_IDLE:
      if (l <= 1)
        return;
      l = 2;
      break;
    case SMART_CARD_TOWITOKO_ACTIVATE:
      if (l < 1)
        return;
      l = 1;
      break;
    case SMART_CARD_TOWITOKO_ATR_H:
    case SMART_CARD_TOWITOKO_ATR_L:
      if (*p != 0x3b)
        {
          SSH_DEBUG(4, ("Towitoko: No sync char found from %s", sc->name));
          ssh_buffer_clear(sc->buffer_in);
        }
      else
        {
          int len;

          ssh_cancel_timeouts(sc_send_atr, sc);
          len = (p[1] & 0x0f) + 2;
          if (p[1] & 0x10) len++;
          if (p[1] & 0x20) len++;
          if (p[1] & 0x40) len++;
          if (p[1] & 0x80) len++;
          if (l < len) return;
          SSH_DEBUG(6, ("Towitoko: Got attr from %s", sc->name));
          ssh_buffer_consume(sc->buffer_in, len);
          sc->state = SMART_CARD_ATR_RECEIVED;
          append_command(sc, 0xa0, 0xf2, 0x00, 0x00, 22, NULL, 0);
          sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
        }
      return;
      break;
    case SMART_CARD_ATR_RECEIVED:
      if (l < 1 + 22 + 2)
        return;
      if (*p != 0xf2)
        {
          SSH_DEBUG(4, ("Towitoko: Invalid response to status from %s",
                        sc->name));
          ssh_buffer_clear(sc->buffer_in);
          return;
        }
      SSH_DEBUG(6, ("Towitoko: Got Status from %s", sc->name));
      ssh_buffer_consume(sc->buffer_in, 22);
      sc->state = SMART_CARD_DONE;
      return;
      break;
    default:
      break;
    }
  if (sc_calc_towitoko_checksum(0x01, p, l) != 0x01)
    {
      SSH_DEBUG(20, ("Towitoko: Input checksum doesn't match, result is %02x from %s",
                    sc_calc_towitoko_checksum(0x01, p, l), sc->name));
      ssh_buffer_clear(sc->buffer_in);
      return;
    }
  switch (sc->state)
    {
    case SMART_CARD_IDLE:
      if (*p & 0x40)
        {
          SSH_DEBUG(5, ("Towitoko: Card inside, sending activate to %s",
                        sc->name));
          sc->state = SMART_CARD_TOWITOKO_ACTIVATE;
          append_str(sc, (unsigned char *) "\x60\x0f", 2);
          sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
          ssh_cancel_timeouts(sc_send_check, sc);
        }
      else
        {
          ssh_cancel_timeouts(sc_send_check, sc);
          ssh_register_timeout(2, 0, sc_send_check, sc);
        }
      ssh_buffer_consume(sc->buffer_in, 2);
      break;
    case SMART_CARD_TOWITOKO_ACTIVATE:
      if (l != 1)
        {
          SSH_DEBUG(3, ("Towitoko: Too much data from card activate from %s",
                        sc->name));
        }
      else
        {
          SSH_DEBUG(5, ("Towitoko: Card activated, sending atr to %s",
                        sc->name));
          sc->state = SMART_CARD_TOWITOKO_ATR_H;
          append_str(sc, (unsigned char *) "\x80\x6f\x00\x05", 4);
          sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
          ssh_register_timeout(2, 0, sc_send_atr, sc);
        }
      ssh_buffer_consume(sc->buffer_in, 1);
      break;
    }
}

void sc_test_towitoko(void *ctx)
{
  SmartCard sc = ctx;
  
  sc->type = SMART_CARD_READER_TOWITOKO;
  SSH_DEBUG(5, ("Sending check to %s", sc->name));
  append_str(sc, (unsigned char *) "\x03", 1);
  sc_stream_callback(SSH_STREAM_CAN_OUTPUT, sc);
  sc->type = SMART_CARD_READER_UNKNOWN;
  ssh_register_timeout(5, 0, sc_test_towitoko, sc);
}

void sc_test_setec(void *ctx);

void sc_test_setec_off(void *ctx)
{
  SmartCard sc = ctx;
  
  SSH_DEBUG(6, ("Clearing RTS for %s", sc->name));
  if (!ssh_serial_stream_modem_clear(sc->stream, SSH_SERIAL_MODEM_RTS))
    ssh_fatal("ssh_serial_stream_modem_clear for %s failed", sc->name);

  ssh_register_timeout(5, 0, sc_test_setec, sc);
}

void sc_test_setec(void *ctx)
{
  SmartCard sc = ctx;

  SSH_DEBUG(6, ("Setting RTS for %s", sc->name));
  if (!ssh_serial_stream_modem_set(sc->stream, SSH_SERIAL_MODEM_RTS))
    ssh_fatal("ssh_serial_stream_modem_set for %s failed", sc->name);

  ssh_register_timeout(0, 500000, sc_test_setec_off, sc);
}

void sc_process_input(SmartCard sc)
{
  unsigned char *p;
  size_t l;

  p = ssh_buffer_ptr(sc->buffer_in);
  l = ssh_buffer_len(sc->buffer_in);

restart:
  switch (sc->type)
    {
    case SMART_CARD_READER_UNKNOWN:
      if (*p == 0x3b)
        {
          ssh_cancel_timeouts(sc_test_setec, sc);
          ssh_cancel_timeouts(sc_test_setec_off, sc);
          ssh_cancel_timeouts(sc_test_towitoko, sc);
          sc->type = SMART_CARD_READER_SETEC;
          SSH_DEBUG(3, ("Reader %s is setec", sc->name));
          goto restart;
        }
      if ((*p & 0x3f) == 0 && l > 1 &&
          sc_calc_towitoko_checksum(0x01, p, 2) == 0x01)
        {
          SSH_DEBUG(3, ("Reader %s is towitoko", sc->name));
          ssh_cancel_timeouts(sc_test_setec, sc);
          ssh_cancel_timeouts(sc_test_setec_off, sc);
          ssh_cancel_timeouts(sc_test_towitoko, sc);
          sc->type = SMART_CARD_READER_TOWITOKO;
          goto restart;
        }
      if ((*p & 0x3f) == 0 && l == 1)
        return;
      ssh_buffer_clear(sc->buffer_in);
      break;
    case SMART_CARD_READER_SETEC:
      sc_process_setec(sc);
      break;
    case SMART_CARD_READER_TOWITOKO:
      sc_process_towitoko(sc);
      break;
    }
}

void sc_check_modem_status(void *ctx)
{
  SmartCard sc = ctx;
  SshSerialModemControl modem;

  if (!ssh_serial_stream_modem_get(sc->stream, &modem))
    ssh_fatal("ssh_serial_stream_modem_get for %s failed", sc->name);

  if (modem != sc->modem)
    {
      SSH_DEBUG(3, ("Modem status changed for %s, old = 0x%x, new = 0x%x",
                    sc->name, sc->modem, modem));
    }
  sc->modem = modem;
  ssh_register_timeout(0, 500000, sc_check_modem_status, sc);
}

int main(int argc, char **argv)
{
  SmartCard sc1, sc2;
  char *tty1 = "/dev/tty00";
  char *tty2 = "/dev/tty01";
  const char *debug_string = "*=3,Main=6";

  if (argc >= 2)
    tty1 = argv[1];

  if (argc >= 3)
    tty2 = argv[2];

  ssh_debug_set_level_string(debug_string);
  ssh_event_loop_initialize();
  
  sc1 = sc_open(tty1, "tty00");
  ssh_register_timeout(5, 0, sc_test_towitoko, sc1);
  ssh_register_timeout(5, 0, sc_test_setec, sc1);
  ssh_register_timeout(0, 500000, sc_check_modem_status, sc1);

#ifdef TTY_LINE_01
  sc2 = sc_open(tty2, "tty01");
  ssh_register_timeout(5, 0, sc_test_towitoko, sc2);
  ssh_register_timeout(5, 0, sc_test_setec, sc2);
  ssh_register_timeout(0, 500000, sc_check_modem_status, sc2);
  ssh_register_timeout(60, 0, sc_close, sc2);
#endif /* TTY_LINE_01 */

  ssh_register_timeout(60, 0, sc_close, sc1);
  ssh_event_loop_run();

  ssh_event_loop_uninitialize();

  return 0;
}
