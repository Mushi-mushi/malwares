/*
 * salt.c - generate a random salt string for crypt()
 *
 * Written by Marek Michalkiewicz <marekm@i17linuxb.ists.pwr.wroc.pl>,
 * public domain.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: salt.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include "prototypes.h"
#include "defines.h"
#include <sys/time.h>

#ifdef MD5_CRYPT
#include "md5.h"
#include "getdef.h"

/*
 * Generate 8 base64 ASCII characters of random salt.  If MD5_CRYPT_ENAB
 * in /etc/login.defs is "yes", the salt string will be prefixed by "$1$"
 * (magic) and pw_encrypt() will execute the MD5-based FreeBSD-compatible
 * version of crypt() instead of the standard one.
 * TODO: use the Linux 1.3.xx random device?
 */
char *
crypt_make_salt()
{
	struct timeval tv;
	MD5_CTX ctx;
	static char result[16];
	char *cp = result;
	unsigned char tmp[16];
	int i;

	MD5Init(&ctx);

	gettimeofday(&tv, (struct timezone *) 0);
	MD5Update(&ctx, (void *) &tv, sizeof tv);

	i = getpid();
	MD5Update(&ctx, (void *) &i, sizeof i);

	i = clock();
	MD5Update(&ctx, (void *) &i, sizeof i);

	MD5Update(&ctx, result, sizeof result);

	MD5Final(tmp, &ctx);

	if (getdef_bool("MD5_CRYPT_ENAB")) {
		strcpy(cp, "$1$");  /* magic for the new crypt() */
		cp += strlen(cp);
	}
	/* generate 8 chars of salt, the old crypt() will use only first 2 */
	for (i = 0; i < 8; i++)
		*cp++ = i64c(tmp[i] & 077);
	*cp = '\0';
	return result;
}
#else

/*
 * This is the old style random salt generator...
 */
char *
crypt_make_salt()
{
	time_t now;
	static unsigned long x;
	static char result[3];

	time(&now);
	x += now + getpid() + clock();
	result[0] = i64c(((x >> 18) ^ (x >> 6)) & 077);
	result[1] = i64c(((x >> 12) ^ x) & 077);
	result[2] = '\0';
	return result;
}
#endif
