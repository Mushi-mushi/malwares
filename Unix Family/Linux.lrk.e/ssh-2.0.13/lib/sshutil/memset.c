#include "sshincludes.h"

void *memset(void *b, int ch, size_t len)
{
  unsigned char *p = (unsigned char *)b;

  if (ch == 0)
    {
      bzero(b, len);
      return b;
    }
  while (len-- > 0)
    {
      *p++ = ch;
    }
  return b;
}
