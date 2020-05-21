/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat May 25 12:59:19 1996 [huima]

  Vlint32 utilities -- part of the protocol.

  */

#ifndef VLINT32_H
#define VLINT32_H

/* Parse the vlint32 residing in *data. Return the value of the vlint32.
   Return the length of the vlint32 data structure in *length_return,
   if length_return != NULL. */

unsigned long ssh_vlint32_parse(const unsigned char *data,
                            size_t *length_return);

/* Write a vlint32 representing `number' to *data. Return the number
   of bytes written. */

size_t ssh_vlint32_write(unsigned long number,
                           unsigned char *data);

/* Return the length of `number', when converted to vlint32
   presentation. */

size_t ssh_vlint32_length(unsigned long number);
                           
/* Return the length of the vlint32 object, which begins from *data. */

size_t ssh_ssh_vlint32_parse_length(const unsigned char *data);

#endif /* VLINT32_H */
