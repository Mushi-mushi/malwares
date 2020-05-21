/*
 * check_name() - check the new user/group name for validity
 * return value: 1 - OK, 0 - bad name
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: chkname.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include <ctype.h>
#include "defines.h"

int
check_name(name)
	const char *name;
{
	/*
	 * Check for validity.  The name must be at least 1 character in
	 * length, but not more than 8.  It must start with a letter and
	 * contain printable characters, not including ':' and '\n'.
	 */

	if (strlen (name) > 8)
		return 0;

	if (! *name || ! isalpha(*name))
		return 0;

	while (*name) {
		if (*name == ':' || *name == '\n' ||
		    ! isprint(*name))
			return 0;

		name++;
	}

	return 1;
}
