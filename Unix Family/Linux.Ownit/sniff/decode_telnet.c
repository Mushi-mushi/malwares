/*
  decode_telnet.c

  Telnet.
  
  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  
  $Id: decode_telnet.c,v 1.4 2000/11/06 14:08:43 dugsong Exp $
*/

#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include "options.h"
#include "decode.h"

int
decode_telnet(u_char *buf, int len, u_char *obuf, int olen)
{
	if ((len = strip_telopts(buf, len)) == 0)
		return (0);

	if (!is_ascii_string(buf, len))
		return (0);
	
	if (strip_lines(buf, Opt_lines) < 2)
		return (0);
	
	strlcpy(obuf, buf, olen);
	
	return (strlen(obuf));
}

