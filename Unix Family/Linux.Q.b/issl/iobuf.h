/* iobuf.h - I/O buffer
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_IOBUF_H
#define G10_IOBUF_H

#include "types.h"


#define DBG_IOBUF   iobuf_debug_mode


#define IOBUFCTRL_INIT	    1
#define IOBUFCTRL_FREE	    2
#define IOBUFCTRL_UNDERFLOW 3
#define IOBUFCTRL_FLUSH     4
#define IOBUFCTRL_DESC	    5
#define IOBUFCTRL_CANCEL    6
#define IOBUFCTRL_USER	    16

typedef struct iobuf_struct *IOBUF;

/* fixme: we should hide most of this stuff */
struct iobuf_struct {
    int use;	       /* 1 input , 2 output, 3 temp */
    unsigned long nlimit;
    unsigned long nbytes; /* used together with nlimit */
    unsigned long ntotal; /* total bytes read (position of stream) */
    int nofast; 	/* used by the iobuf_get() */
    void *directfp;
    struct {
	size_t size;   /* allocated size */
	size_t start;  /* number of invalid bytes at the begin of the buffer */
	size_t len;    /* currently filled to this size */
	byte *buf;
    } d;
    int filter_eof;
    int error;
    int (*filter)( void *opaque, int control,
		   IOBUF chain, byte *buf, size_t *len);
    void *filter_ov;	/* value for opaque */
    int filter_ov_owner;
    char *real_fname;
    IOBUF chain;	/* next iobuf used for i/o if any (passed to filter) */
    int no, subno;
    const char *desc;
    void *opaque;      /* can be used to hold any information	 */
		       /* this value is copied to all instances */
    struct {
	size_t size;   /* allocated size */
	size_t start;  /* number of invalid bytes at the begin of the buffer */
	size_t len;    /* currently filled to this size */
	byte *buf;
    } unget;
};

int iobuf_debug_mode;

IOBUF iobuf_alloc(int use, size_t bufsize);
IOBUF iobuf_temp(void);
IOBUF iobuf_temp_with_content( const char *buffer, size_t length );
IOBUF iobuf_open( const char *fname );
IOBUF iobuf_fdopen( int fd, const char *mode );
IOBUF iobuf_fopen( const char *fname, const char *mode );
IOBUF iobuf_create( const char *fname );
IOBUF iobuf_append( const char *fname );
IOBUF iobuf_openrw( const char *fname );
int   iobuf_close( IOBUF iobuf );
int   iobuf_cancel( IOBUF iobuf );

int iobuf_push_filter( IOBUF a, int (*f)(void *opaque, int control,
		       IOBUF chain, byte *buf, size_t *len), void *ov );
int iobuf_push_filter2( IOBUF a,
		    int (*f)(void *opaque, int control,
		    IOBUF chain, byte *buf, size_t *len),
		    void *ov, int rel_ov );
int iobuf_flush(IOBUF a);
void iobuf_clear_eof(IOBUF a);
#define iobuf_set_error(a)    do { (a)->error = 1; } while(0)
#define iobuf_error(a)	      ((a)->error)

void iobuf_set_limit( IOBUF a, unsigned long nlimit );

ulong iobuf_tell( IOBUF a );
int   iobuf_seek( IOBUF a, ulong newpos );

int  iobuf_readbyte(IOBUF a);
int  iobuf_read(IOBUF a, byte *buf, unsigned buflen );
unsigned iobuf_read_line( IOBUF a, byte **addr_of_buffer,
			  unsigned *length_of_buffer, unsigned *max_length );
int  iobuf_peek(IOBUF a, byte *buf, unsigned buflen );
int  iobuf_writebyte(IOBUF a, unsigned c);
int  iobuf_write(IOBUF a, byte *buf, unsigned buflen );
int  iobuf_writestr(IOBUF a, const char *buf );

void iobuf_flush_temp( IOBUF temp );
int  iobuf_write_temp( IOBUF a, IOBUF temp );
size_t iobuf_temp_to_buffer( IOBUF a, byte *buffer, size_t buflen );
void iobuf_unget_and_close_temp( IOBUF a, IOBUF temp );

u32 iobuf_get_filelength( IOBUF a );
const char *iobuf_get_real_fname( IOBUF a );
const char *iobuf_get_fname( IOBUF a );

void iobuf_set_block_mode( IOBUF a, size_t n );
void iobuf_set_partial_block_mode( IOBUF a, size_t len );
int  iobuf_in_block_mode( IOBUF a );

/* get a byte form the iobuf; must check for eof prior to this function
 * this function returns values in the range 0 .. 255 or -1 to indicate EOF
 * iobuf_get_noeof() does not return -1 to indicate EOF, but masks the
 * returned value to be in the range 0 ..255.
 */
#define iobuf_get(a)  \
     (	((a)->nofast || (a)->d.start >= (a)->d.len )?  \
	iobuf_readbyte((a)) : ( (a)->nbytes++, (a)->d.buf[(a)->d.start++] ) )
#define iobuf_get_noeof(a)    (iobuf_get((a))&0xff)

/* write a byte to the iobuf and return true on write error
 * This macro does only write the low order byte
 */
#define iobuf_put(a,c)	iobuf_writebyte(a,c)

#define iobuf_where(a)	"[don't know]"
#define iobuf_id(a)	((a)->no)

#define iobuf_get_temp_buffer(a) ( (a)->d.buf )
#define iobuf_get_temp_length(a) ( (a)->d.len )
#define iobuf_is_temp(a)	 ( (a)->use == 3 )

#endif /*G10_IOBUF_H*/
