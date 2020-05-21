/*

bufzip.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Wed Oct 25 22:12:46 1995 ylo

A generic wrapper for various compression methods.

*/

/*
 * $Id: bufzip.c,v 1.8 1998/07/24 15:05:01 mjos Exp $
 * $Log: bufzip.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "bufzip.h"
#include "zlib.h"

typedef enum {
  SSH_COMPRESS_NONE,
  SSH_COMPRESS_ZLIB
} SshCompressionMethod;

struct SshCompressionRec
{
  SshCompressionMethod method;
  Boolean for_compression;
  SshBuffer *buffer;
  z_stream z_stream;
};

struct {
  const char *name;
  SshCompressionMethod method;
  unsigned int level;
} ssh_compression_methods[] =
  {
    { "none", SSH_COMPRESS_NONE },
    { "zlib", SSH_COMPRESS_ZLIB, 6 },
    { NULL }
  };


/* Allocates and initializes a compression context.  `name' is the name of
   the compression method to use.  This returns NULL if the given name is
   not valid.  The returned object must be freed with ssh_compress_free
   when no longer needed.  The `for_compression' flag should be TRUE if the
   object is to be used for compression, and FALSE if it is for
   uncompression. */

SshCompression ssh_compress_allocate(const char *name,
				     Boolean for_compression)
{
  SshCompression z;
  int i;

  /* Find the compression method from the table. */
  for (i = 0; ssh_compression_methods[i].name != NULL; i++)
    if (strcmp(ssh_compression_methods[i].name, name) == 0)
      break;
  if (ssh_compression_methods[i].name == NULL)
    return NULL;
      
  /* Allocate the context structure. */
  z = ssh_xmalloc(sizeof(*z));
  memset(z, 'A', sizeof(*z));
  z->method = ssh_compression_methods[i].method;
  z->for_compression = for_compression;
  z->buffer = ssh_buffer_allocate();
  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      break;

    case SSH_COMPRESS_ZLIB:
      /* Initialize the compression stream for the appropriate operation.
	 For this algorithm, we use the compression level from the table. */
      z->z_stream.zalloc = Z_NULL;
      z->z_stream.zfree = Z_NULL;
      z->z_stream.opaque = Z_NULL;
      if (for_compression)
	deflateInit(&z->z_stream, ssh_compression_methods[i].level);
      else
	inflateInit(&z->z_stream);
      break;

    default:
      ssh_fatal("ssh_compress_allocate: bad method %d", (int)z->method);
      /*NOTREACHED*/
    }

  return z;
}

/* Frees the given compression context. */

void ssh_compress_free(SshCompression z)
{
  ssh_buffer_free(z->buffer);
  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      break;

    case SSH_COMPRESS_ZLIB:
      if (z->for_compression)
	deflateEnd(&z->z_stream);
      else
	inflateEnd(&z->z_stream);
      break;

    default:
      ssh_fatal("ssh_compress_free: unknown method %d", (int)z->method);
      /*NOTREACHED*/
    }

  /* Fill with garbage to ease debugging. */
  memset(z, 'F', sizeof(*z));

  /* Free the context. */
  ssh_xfree(z);
}

/* Returns the names of the supported algorithms as a comma-separated
   list.  The caller must free the returned string with ssh_xfree when no longer
   needed. */

char *ssh_compress_get_supported(void)
{
  SshBuffer buffer;
  char *cp;
  int i;

  /* Construct the list of algorithm names from the array. */
  ssh_buffer_init(&buffer);
  for (i = 0; ssh_compression_methods[i].name != NULL; i++)
    {
      if (i != 0)
	ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
      ssh_buffer_append(&buffer, (unsigned char *)
			ssh_compression_methods[i].name,
			strlen(ssh_compression_methods[i].name));
    }
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  cp = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
  return cp;
}

/* Returns true if the given compression method does not actually compress
   (it just returns the input data). */

Boolean ssh_compress_is_none(SshCompression z)
{
  return z->method == SSH_COMPRESS_NONE;
}

/* Compresses the given data into output_buffer using zlib.
   This is an internal function. */

void ssh_zlib_compress(z_stream *outgoing_stream, const unsigned char *data,
		       size_t len, SshBuffer *output_buffer)
{
  unsigned char buf[4096];
  int status;

  /* Prepare source data. */
  outgoing_stream->next_in = (void *)data;
  outgoing_stream->avail_in = len;

  /* Loop compressing until deflate() returns with avail_out != 0. */
  do
    {
      /* Set up fixed-size output buffer. */
      outgoing_stream->next_out = buf;
      outgoing_stream->avail_out = sizeof(buf);

      /* Compress as much data into the buffer as possible. */
      if (outgoing_stream->avail_in != 0)
	status = deflate(outgoing_stream, Z_PARTIAL_FLUSH);
      else
	status = deflate(outgoing_stream, Z_SYNC_FLUSH);

      switch (status)
	{
	case Z_OK:
	  /* Append compressed data to output_buffer. */
	  ssh_buffer_append(output_buffer, buf,
			sizeof(buf) - outgoing_stream->avail_out);
	  break;
	case Z_STREAM_END:
	  ssh_fatal("ssh_zlib_compress: deflate returned Z_STREAM_END");
	  /*NOTREACHED*/
	case Z_STREAM_ERROR:
	  ssh_fatal("ssh_zlib_compress: deflate returned Z_STREAM_ERROR");
	  /*NOTREACHED*/
	case Z_BUF_ERROR:
	  ssh_fatal("ssh_zlib_compress: deflate returned Z_BUF_ERROR");
	  /*NOTREACHED*/
	default:
	  ssh_fatal("ssh_zlib_compress: deflate returned %d", status);
	  /*NOTREACHED*/
	}
    }
  while (outgoing_stream->avail_out == 0);
}

/* Uncompresses the given data into output_buffer using zlib.
   This is an internal function. */

void ssh_zlib_uncompress(z_stream *incoming_stream, const unsigned char *data,
			 size_t len, SshBuffer *output_buffer)
{
  unsigned char buf[4096];
  int status;

  /* Prepare source data. */
  incoming_stream->next_in = (void *)data;
  incoming_stream->avail_in = len;

  incoming_stream->next_out = buf;
  incoming_stream->avail_out = sizeof(buf);

  for (;;)
    {
      status = inflate(incoming_stream, Z_PARTIAL_FLUSH);
      switch (status)
	{
	case Z_OK:
	  ssh_buffer_append(output_buffer, buf,
			sizeof(buf) - incoming_stream->avail_out);
	  incoming_stream->next_out = buf;
	  incoming_stream->avail_out = sizeof(buf);
	  break;
	case Z_STREAM_END:
	  ssh_fatal("ssh_zlib_uncompress: inflate returned Z_STREAM_END");
	  /*NOTREACHED*/
	case Z_DATA_ERROR:
	  ssh_fatal("ssh_zlib_uncompress: inflate returned Z_DATA_ERROR");
	  /*NOTREACHED*/
	case Z_STREAM_ERROR:
	  ssh_fatal("ssh_zlib_uncompress: inflate returned Z_STREAM_ERROR");
	  /*NOTREACHED*/
	case Z_BUF_ERROR:
	  /* Comments in zlib.h say that we should keep calling inflate()
	     until we get an error.  This appears to be the error that we
	     get. */
	  return;
	case Z_MEM_ERROR:
	  ssh_fatal("ssh_zlib_uncompress: inflate returned Z_MEM_ERROR");
	  /*NOTREACHED*/
	default:
	  ssh_fatal("ssh_zlib_uncompress: inflate returned %d", status);
	}
    }
}

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
			 size_t len, SshBuffer *output_buffer)
{
  switch (z->method)
    {
    case SSH_COMPRESS_NONE:
      ssh_buffer_append(output_buffer, data, len);
      break;

    case SSH_COMPRESS_ZLIB:
      if (z->for_compression)
	ssh_zlib_compress(&z->z_stream, data, len, output_buffer);
      else
	ssh_zlib_uncompress(&z->z_stream, data, len, output_buffer);
      break;
      
    default:
      ssh_fatal("ssh_compress_buffer: unknown method %d", (int)z->method);
    }
}
