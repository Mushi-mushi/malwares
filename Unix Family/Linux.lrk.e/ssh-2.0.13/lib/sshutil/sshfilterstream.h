/*

sshfilterstream.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

An object for filtering a data stream bidirectionally.  The object
allows callbacks to modify and filter data bidirectionally, and allow
them to disconnect the connection.

*/

#ifndef SSHFILTERSTREAM_H
#define SSHFILTERSTREAM_H

#include "sshstream.h"
#include "sshbuffer.h"

/* Operation codes returned by filter functions.  */

/* Indicates that the given number of bytes should be passed through.
   The number should not be greater than the number of bytes in the
   buffer.  The value zero indicates to keep all bytes in the buffer,
   and call the filter function again when more data has been
   received.  If ``nbytes'' is less than the number of bytes in
   buffer, the remaining bytes are kept in the buffer. */
#define SSH_FILTER_ACCEPT(nbytes)  (nbytes)

/* Instructs to keep the data in buffer, and call the filter again when
   more data has been received.  Returning this has the same effect as
   accepting zero bytes. */
#define SSH_FILTER_HOLD	           0

/* Indicates that the stream should be immediately disconnected.  All bytes
   in the buffer are thrown away, and EOF will be returned by the stream
   in both directions.  No more data will be accepted.  The filter functions
   will not be called again (but ``destroy'' will be called when the
   application closes the stream). */
#define SSH_FILTER_DISCONNECT	   -1

/* Indicates that the stream should be shortcircuited in both directions.
   Data still in buffers is flushed in both directions, and from then on,
   any data will be directly transmitted through.  The filter functions
   will not be called again (but ``destroy'' will be called when the
   application closes the stream). */
#define SSH_FILTER_SHORTCIRCUIT	   -2

/* Filter function.  This should analyze data in the buffer, and
   return one of the values defined above.  ``data'' contains data
   received from the stream so far.  Data up to ``offset'' has been
   already accepted, and should not be touched.  This is allowed to
   modify data after offset, and even add/remove data there.  When
   accepting bytes, data before ``offset'' should not be counted.  It
   has already been accepted, and is only kept in the buffer until it
   can be written out.
     `data'         data received so far; contents may be modified
     `offset'	    offset where unaccepted data starts
     `eof_received' TRUE if EOF has already been received in this direction
     `context'      context argument from creating the filter. */
typedef int (*SshFilterProc)(SshBuffer *data, size_t offset,
			     Boolean eof_received, void *context);

/* Creates a stream that can be used to filter data to/from another
   stream.  ``stream'' is an already existing stream whose data is to
   be filter.  It is wrapped into the filter stream, and will be
   closed automatically when the filter stream is closed.
   ``to_stream_filter'', if non-NULL, is a filter to call whenever
   data is written to the returned stream (and is on its way to
   ``stream'').  ``from_stream_filter'' (if non-NULL) is called
   whenever data is received from ``stream''.  ``destroy'' (if
   non-NULL) is called when the returned stream is closed; it can be
   used to free ``context''.  The filter functions must ensure that the
   buffer does not grow unboundedly.
     `stream'             stream whose data is to be filtered
     `max_buffer_size'    maximum number of bytes to buffer
     `to_stream_filter'   filter for data going to ``stream'', or NULL
     `from_stream_filter' filter for data coming from ``stream'', or NULL
     `destroy'            called when the returned stream is closed, or NULL
     `context'            context argument to pass to the functions.
   The filter functions are not allowed to directly destroy the stream. */
SshStream ssh_stream_filter_create(SshStream stream,
				   size_t max_buffer_size,
				   SshFilterProc to_stream_filter,
				   SshFilterProc from_stream_filter,
				   void (*destroy)(void *context),
				   void *context);

#endif /* SSHFILTERSTREAM_H */
