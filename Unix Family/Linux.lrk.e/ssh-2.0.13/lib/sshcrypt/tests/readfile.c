/*

  readfile.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Mar 27 19:40:13 1997 [mkojo]

  File routines for testing cryptolibrary. 

  */

/*
 * $Id: readfile.c,v 1.6 1998/06/02 21:37:02 kivinen Exp $
 * $Log: readfile.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "readfile.h"

/*
  File has the format:

  %   is a comment
    ignored
  0x  denotes hex string (of variable length) msb-first
    type value = 1
  ".. " for ascii strings.
  label ".." for labels 
  
 */

typedef struct RFContextRec
{
  int set;
  unsigned char buffer[BUFFER_SIZE];
  unsigned char outbuf[BUFFER_SIZE];
  int len;
  int pos;
  FILE *fp;
} RFContext;

RFContext rf_context = { RF_NOT_INITIALIZED, {0x00} };

const unsigned char hextable[128] =
{
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

RFStatus ssh_t_read_init(const char *file)
{
  rf_context.fp = fopen(file, "r");
  if (rf_context.fp == NULL)
    return RF_FAILED;

  rf_context.set = RF_READ;
  rf_context.len = 0;
  rf_context.pos = 0;
  
  return RF_READ;
}

RFStatus ssh_t_write_init(const char *file)
{
  rf_context.fp = fopen(file, "w");
  if (rf_context.fp == NULL)
    return RF_FAILED;

  rf_context.set = RF_WRITE;
  rf_context.len = 0;
  rf_context.pos = 0;
  
  return RF_WRITE;
}

void ssh_t_close()
{
  fclose(rf_context.fp);
}

RFStatus ssh_t_read_token(unsigned char **buf, size_t *len)
{
  unsigned char *ptr;
  int i, j;
  int state;
#define STATE_READ_LINE 1
#define STATE_NEXT_TOKEN 2

  state = STATE_NEXT_TOKEN;

  *buf = NULL;
  *len = 0;

  if (rf_context.set != RF_READ)
    return RF_NOT_INITIALIZED;
  
  while (1)
    {
      switch (state)
	{
	case STATE_READ_LINE:
	  ptr = (unsigned char *) fgets((char *) rf_context.buffer,
					BUFFER_SIZE, rf_context.fp);
	  if (ptr == NULL)
	    {
	      rf_context.set = RF_NOT_INITIALIZED;
	      return RF_EMPTY;
	    }
	  rf_context.len = strlen((char *) rf_context.buffer);
	  rf_context.pos = 0;
	  
	  /* Move to the next state. */
	  state = STATE_NEXT_TOKEN;
	case STATE_NEXT_TOKEN:

	  /* Change state. */
	  if (rf_context.len <= rf_context.pos)
	    {
	      state = STATE_READ_LINE;
	      break;
	    }

	  /* Skip possible spaces. */
	  for (; isspace(rf_context.buffer[rf_context.pos]) &&
		 rf_context.pos < rf_context.len; rf_context.pos++)
	    ;

	  if (rf_context.pos >= rf_context.len)
	    {
	      state = STATE_READ_LINE;
	      break;
	    }
	  
	  /* Identify. */

	  switch (rf_context.buffer[rf_context.pos])
	    {
	    case '0':
	      if (rf_context.buffer[rf_context.pos+1] == 'x')
		{
		  /* HEX */

		  rf_context.pos += 2;
		  
		  /* First just count. */
		  for (i = rf_context.pos;
		       isxdigit(rf_context.buffer[i]) && i < rf_context.len;
		       i++)
		    ;

		  /* Output pos. */
		  j = 0;
		  
		  /* If odd sized. */
		  if ((i - rf_context.pos) & 0x1)
		    rf_context.outbuf[j++] =
		      hextable[rf_context.buffer[rf_context.pos++]];

		  for (; rf_context.pos < i; rf_context.pos += 2, j++)
		    {
		      rf_context.outbuf[j] =
			((hextable[rf_context.buffer[rf_context.pos]]) << 4) |
			hextable[rf_context.buffer[rf_context.pos + 1]];
		    }

		  *len = j;
		  *buf = rf_context.outbuf;
		  
		  return RF_HEX;
		  break;
		}
	      ssh_fatal("ssh_t_read_token: internal error (1).");
	      break;
	    case '"':
	      /* Ascii text. */
	      
	      rf_context.pos += 1;
	      
	      /* First just count. */
	      for (i = rf_context.pos; rf_context.buffer[i] != '"' &&
		   isascii(rf_context.buffer[i]) && i < rf_context.len;
		   i++)
		;

	      if (rf_context.buffer[i] != '"')
		{
		  rf_context.pos = i;
		  return RF_CORRUPTED;
		}

	      /* Copy. */
	      memcpy(rf_context.outbuf,
		     rf_context.buffer + rf_context.pos,
		     i - rf_context.pos);

	      *buf = rf_context.outbuf;
	      *len = i - rf_context.pos;
	      rf_context.pos = i + 1;
	      return RF_ASCII;
	      break;
            case '%':
	      /* Comment. */
	      rf_context.pos = rf_context.len;
	      break;
	    case 'l':
	      if (rf_context.len - rf_context.pos > 5)
		{
		  /* Possibly a label. */
		  if (memcmp(rf_context.buffer + rf_context.pos,
			     "label", 5) == 0)
		    {
		      rf_context.pos += 5;

		      /* Read the following ascii string. */
		      if (ssh_t_read_token(buf, len) != RF_ASCII)
			{
			  return RF_FAILED;
			}
		      return RF_LABEL;
		    }
		}
	    default:
	      ssh_fatal("ssh_t_read_token: internal error (2).");
	      break;
	    }
	  break;
	default:
	  ssh_fatal("ssh_t_read_token: internal error (3).");
	  break;
	}
    }
  return RF_FAILED;
}

void ssh_t_write_token(RFStatus type, unsigned char *buf, size_t len)
{
  int i;

  if (rf_context.set != RF_WRITE)
    ssh_fatal("ssh_t_write_token: not initialized properly.");
  
  switch (type)
    {
    case RF_HEX:

      fprintf(rf_context.fp, "0x");
      for (i = 0; i < len; i++)
	{
	  fprintf(rf_context.fp, "%02x", buf[i]);
	}
      fprintf(rf_context.fp, " ");
      break;
      
    case RF_ASCII:
      fprintf(rf_context.fp, "\"");
      for (i = 0; i < len; i++)
	{
	  fprintf(rf_context.fp, "%c", buf[i]);
	}
      fprintf(rf_context.fp, "\" ");
      break;

    case RF_COMMENT:
      fprintf(rf_context.fp, "%% ");
      for (i = 0; i < len; i++)
	{
	  fprintf(rf_context.fp, "%c", buf[i]);
	}
      fprintf(rf_context.fp, "\n");
      break;

    case RF_LINEFEED:
      fprintf(rf_context.fp, "\n");
      break;

    case RF_LABEL:
      fprintf(rf_context.fp, "label ");
      ssh_t_write_token(RF_ASCII, buf, len);
      break;
      
    default:
      /* Don't mind other types. It is not an error. */
      break;
    }
}

/* readfile.c */
