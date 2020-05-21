/*

sshencode.h

Author: Tero Kivinen <kivinen@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

Helper functions for encoding/decoding binary data.

*/

#ifndef SSHENCODE_H
#define SSHENCODE_H

#include "sshbuffer.h"

/* An invalid pointer to indicate that SshDecoder should free data. */
#define SSH_DECODE_FREE (const unsigned char *)1

/* Function to encode data into the buffer.  *app is a variable argument
   list that should be stepped over arguments to this format.  This should
   append the encoded format at the end of the buffer. */
typedef void (*SshEncoder)(SshBuffer *buffer, va_list *app);

/* Function to decode data from the buffer.  `buf' points to the data
   to decode, `len' is the amount of data available, and *app is a variable
   argument list that should be stepped over arguments to this format.
   Formats should normally allow arguments to be NULL to allow skipping formats
   without storing them.  This should return the number of bytes processed,
   or 0 on error.

   In the case that parsing fails after this call has successfully returned,
   this will be called again with `buf' set to SSH_DECODE_FREE.  That case
   should be checked, and any memory allocated by the original call should
   be freed.  Other arguments are return value are ignored in this case. */
typedef size_t (*SshDecoder)(const unsigned char *buf, size_t len,
                             va_list *app);

/* The packet encoding/decoding functions take a variable number of arguments,
   and decode data from a SshBuffer or a character array as specified by a
   format.  Each element of the format contains a type specifier, and
   arguments depending on the type specifier.  The list must end with a
   SSH_FORMAT_END specifier. */

typedef enum {
  /* Specifies a string with vlint32-coded length.  This has two arguments.
     For encoding,
         const unsigned char *data
         size_t len
     For decoding,
         unsigned char **data_return
         size_t *len_return
     When decoding, either or both arguments may be NULL, in which case they
     are not stored.  The returned data is allocated by ssh_xmalloc, and an
     extra nul (\0) character is automatically added at the end to make it
     easier to retrieve strings. */
  SSH_FORMAT_VLINT32_STR,       /* char *, size_t */

  /* This code can only be used while decoding.  This specifies string with
     vlint32-coded length.  This has two arguments:
       const unsigned char **data_return
       size_t *len_return
     Either argument may be NULL.  *data_return is set to point to the data
     in the packet, and *len_return is set to the length of the string.
     No null character is stored, and the string remains in the original
     buffer.  This should only be used with ssh_decode_array, as there
     is no guarantee that decoding from a buffer will not rearrange buffer
     data in future versions. */
  SSH_FORMAT_VLINT32_STR_NOCOPY,/* char *, size_t */

  /* A string with uint32-coded length.  Otherwise identical to
     SSH_FORMAT_VLINT32_STR. */
  SSH_FORMAT_UINT32_STR,        /* char *, size_t */

  /* A string with uint32-coded lenght.  Otherwise identical to
     SSH_FORMAT_VLINT32_STR_NOCOPY. */
  SSH_FORMAT_UINT32_STR_NOCOPY, /* char *, size_t */

  /* A vlint32-coded integer value.  For encoding, this has a single
     "unsigned long" argument (the value), and for decoding an
     "unsigned long *" argument, where the value will be stored.  The argument
     may be NULL in which case the value is not stored. */
  SSH_FORMAT_VLINT32,           /* SshUInt32 */

  /* An 32-bit MSB first integer value.  Otherwise like SSH_FORMAT_VLINT32. */
  SSH_FORMAT_UINT32,            /* SshUInt32, note that if you encode constant
                                   integer, you still must use (SshUInt32) cast
                                   before it. Also enums must be casted to
                                   SshUInt32 before encoding. */

  /* A boolean value.  For encoding, this has a single "Boolean" argument.
     For decoding, this has a "Boolean *" argument, where the value will
     be stored.  The argument may be NULL in which case the value is not
     stored. */
  SSH_FORMAT_BOOLEAN,           /* Boolean */

  /* A multiple-precision integer value.  The argument is of type "SshInt *".
     When decoding, the SshInt must already have been initialized.  The
     value may also be NULL when decoding, in which case the value is not
     stored.  The format is 32-bit MSB first number of bits, followed by
     (bits+7)/8 bytes of data, MSB first (unsigned only). */
  SSH_FORMAT_MP_INT,            /* SshInt * (both decode / encode) */

  /* A single one-byte character.  The argument is of type "unsigned int"
     when encoding, and of type "unsigned int *" when decoding.  The value
     may also be NULL when decoding, in which case the value is ignored. */
  SSH_FORMAT_CHAR,              /* unsigned int */

  /* A fixed-length character array, without explicit length.  When
     encoding, the arguments are
         const unsigned char *buf
         size_t len
     and when decoding,
         unsigned char *buf
         size_t len
     The buffer must be preallocated when decoding; data is simply copied
     there.  `buf' may also be NULL, in which the value is ignored. */
  SSH_FORMAT_DATA,              /* char * (fixed length!), size_t */

  /* Extended, application-defined format.  The first argument is
     a function to do the encoding or decoding.  It is followed by a 
     format-specific number of additional arguments.  Applications can
     register new formats using ssh_encode_register_format and
     ssh_decode_register_format.  For encoding, the first argument must be
     of type SshEncoder, and for decoding it must be of type SshDecoder. */
  SSH_FORMAT_EXTENDED,

  /* A 64-bit MSB first integer value.  For encoding, this has a single
     "SshUInt64" argument (the value), and for decoding an
     "SshUInt64 *" argument, where the value will be stored.  The argument
     may be NULL in which case the value is not stored. */
  SSH_FORMAT_UINT64,            /* SshUInt64 */
  
  /* Marks end of the argument list. */
  SSH_FORMAT_END = 0x0d0e0a0d
} SshEncodingFormat;

/* Appends data at the end of the buffer as specified by the variable-length
   argument list.  Each element must start with a SshEncodingFormat type,
   be followed by arguments of the appropriate type, and the list must end
   with SSH_FORMAT_END.  This returns the number of bytes added to the
   buffer. */
size_t ssh_encode_buffer(SshBuffer *buffer, ...);

/* Appends data at the end of the buffer as specified by the variable-length
   argument list.  Each element must start with a SshEncodingFormat type,
   be followed by arguments of the appropriate type, and the list must end
   with SSH_FORMAT_END.  This returns the number of bytes added to the
   buffer. */
size_t ssh_encode_va(SshBuffer *buffer, va_list ap);

/* Encodes the given data.  Returns the length of encoded data in bytes, and
   if `buf_return' is non-NULL, it is set to a memory area allocated by
   ssh_xmalloc that contains the data.  The caller should free the data when
   no longer needed. */
size_t ssh_encode_alloc(unsigned char **buf_return, ...);

/* Encodes the given data.  Returns the length of encoded data in bytes, and
   if `buf_return' is non-NULL, it is set to a memory area allocated by
   ssh_xmalloc that contains the data.  The caller should free the data when
   no longer needed. */
size_t ssh_encode_alloc_va(unsigned char **buf_return, va_list ap);

/* Decodes data from the given byte array as specified by the
   variable-length argument list.  If all specified arguments could be
   successfully parsed, returns the number of bytes parsed (any
   remaining data can be parsed by first skipping this many bytes).
   If parsing any element results in an error, this returns 0 (and
   frees any already allocated data).  Zero is also returned if the
   specified length would be exceeded. */
size_t ssh_decode_array_va(const unsigned char *buf, size_t len, va_list ap);

/* Decodes data from the given byte array as specified by the
   variable-length argument list.  If all specified arguments could be
   successfully parsed, returns the number of bytes parsed (any
   remaining data can be parsed by first skipping this many bytes).
   If parsing any element results in an error, this returns 0 (and
   frees any already allocated data).  Zero is also returned if the
   specified length would be exceeded. */
size_t ssh_decode_array(const unsigned char *buf, size_t len, ...);

/* Decodes and consumes data from the given buffer as specified by the
   variable-length argument list.  If all the specified arguments could he
   successfully parsed, returns the number of bytes parsed and consumes the
   parsed data from the buffer.  If parsing results in an error, or the buffer
   does not contain enough data, 0 is returned and nothing is consumed from
   the buffer. */
size_t ssh_decode_buffer(SshBuffer *buffer, ...);

#endif /* SSHENCODE_H */
