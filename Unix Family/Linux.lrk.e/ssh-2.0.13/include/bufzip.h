/*

bufzip.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Oct 25 22:12:46 1995 ylo

Compression of data in buffers.

*/

/*
 * $Id: bufzip.h,v 1.5 1998/07/24 15:05:01 mjos Exp $
 * $Log: bufzip.h,v $
 * $EndLog$
 */

#ifndef BUFZIP_H
#define BUFZIP_H

#include "sshbuffer.h"

/* Data type for a compression context. */
typedef struct SshCompressionRec *SshCompression;

/* Allocates and initializes a compression context.  `name' is the name of
   the compression method to use.  This returns NULL if the given name is
   not valid.  The returned object must be freed with ssh_compress_free
   when no longer needed.  The `for_compression' flag should be TRUE if the
   object is to be used for compression, and FALSE if it is for
   uncompression. */
SshCompression ssh_compress_allocate(const char *name,
				     Boolean for_compression);

/* Frees the given compression context. */
void ssh_compress_free(SshCompression z);

/* Returns the names of the supported algorithms as a comma-separated
   list. The caller must free the returned string with ssh_xfree when no 
   longer needed. */
char *ssh_compress_get_supported(void);

/* Returns true if the given compression method does not actually compress
   (it just returns the input data). */
Boolean ssh_compress_is_none(SshCompression z);

/* Compresses or uncompresses the given data into output_buffer.  The
   performed operations depends on whether the object was created for
   compression or for uncompression.  All data compressed using the
   same object will form a single data stream; however, data will be
   flushed at the end of every call so that each compressed
   `output_buffer' can be decompressed independently by the receiver
   (but in the appropriate order since they together form a single
   compression stream).  This appends the compressed data to the
   output buffer. */
void ssh_compress_buffer(SshCompression z, const unsigned char *data,
			 size_t len, SshBuffer *output_buffer);

#endif /* BUFZIP_H */
